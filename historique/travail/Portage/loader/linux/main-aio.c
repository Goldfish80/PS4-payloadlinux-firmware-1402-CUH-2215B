/*
 * main-aio.c — All-In-One PS4 Linux payload
 *
 * Compile-time flags:
 *   -DVRAM_MB_DEFAULT=<n>   default VRAM size in MB (required)
 *   -DVRAM_MB_MIN=<n>       minimum VRAM size in MB
 *   -DVRAM_MB_MAX=<n>       maximum VRAM size in MB
 */

#include <sys/types.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/thr.h>
#include <time.h>
#include <sys/sysctl.h>
#include "sb_detect.h"


#include "aio_types.h"
#include "fw_detect.h"
#include "fw_offsets.h"
#include "guards-1402.h"
#include "sysctl-subid.h"

static volatile int kernel_stage_result = -1;
static int local_log_fd = -1;

static __attribute__((optimize("O2"))) unsigned int boot_crc32(const char *data, unsigned long long size)
{
    unsigned int crc = 0xffffffffU;
    for (unsigned long long i = 0; i < size; ++i) {
        crc ^= (unsigned char)data[i];
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320U & (0U - (crc & 1U)));
    }
    return crc ^ 0xffffffffU;
}

void* dlopen(const char*, int);
void* dlsym(void*, const char*);

typedef int (*t_sysctlbyname)(const char *, void *, size_t *, const void *, size_t);
void thr_exit(long *state);

static unsigned long long str_len(const char *s)
{
    unsigned long long len = 0;

    while (s && s[len])
        len++;

    return len;
}

static void log_msg(const char *msg)
{
    unsigned long long len = str_len(msg);

    if (len)
        write(1, msg, len);
    if (!len || msg[len - 1] != '\n')
        write(1, "\n", 1);
    if (local_log_fd >= 0) {
        unsigned long long written = 0;
        while (written < len) {
            long n = write(local_log_fd, msg + written, len - written);
            if (n <= 0) break;
            written += (unsigned long long)n;
        }
        if (!len || msg[len - 1] != '\n') write(local_log_fd, "\n", 1);
        fsync(local_log_fd);
    }
}

static void log_result(const char *label, unsigned long long value)
{
    char result[19];
    const char *digits = "0123456789abcdef";
    result[0] = '0'; result[1] = 'x'; result[18] = 0;
    for (int i = 0; i < 16; ++i) result[2+i] = digits[(value >> (60-4*i)) & 15];
    log_msg(label); log_msg(result);
}

// This console-specific build embeds only the checked 14.02 kernel payload.
asm("kexec_1402:\n.incbin \"kexec-build/1402/kexec.bin\"\nkexec_1402_end:\n");

/* Embedded 14.02 entry and end. */
extern char kexec_1402[], kexec_1402_end[];

// Globals set by main() and used by kernel_main()
// kernel_main() runs in kernel context but can still read
// payload globals because the payload's physical memory remains mapped.

static fw_offsets_t *g_fw       = (fw_offsets_t *)0;
static char         *g_kexec_s  = (char *)0;
static char         *g_kexec_e  = (char *)0;


// Helper functions

static fw_offsets_t *find_offsets_by_fw(u16 fw)
{
    u16 norm = normalize_fw_ver(fw);
    for (int i = 0; fw_table[i].fw_ver != 0; i++) {
        if (fw_table[i].fw_ver == norm)
            return &fw_table[i];
    }
    return (fw_offsets_t *)0;
}

/*
 * get_kexec_blob — returns the start/end of the embedded kexec
 * binary according to the normalized firmware version. Switch,
 * to avoid problems with linkers and addresses.
 */
static void get_kexec_blob(u16 norm_fw, char **start, char **end)
{
    switch (norm_fw) {
    case 1402: *start = kexec_1402; *end = kexec_1402_end; break;
    default:   *start = (char *)0;  *end = (char *)0;      break;
    }
}

// Platform-specific helper functions for AIO launch

asm("kexec_load:\nmov %rcx, %r10\nmov $153, %rax\nsyscall\nret");

int kexec_load(char *kernel, unsigned long long kernel_size,
               char *initrd,  unsigned long long initrd_size,
               char *cmdline, int vram_mb);

int read_file(char *path, char **ptr, unsigned long long *sz)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    long length = lseek(fd, 0, SEEK_END);
    if (length <= 0 || length > 128 * 1024 * 1024) {
        close(fd);
        return -1;
    }
    char *buffer = mmap(NULL, (size_t)length + 1, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buffer == MAP_FAILED) { close(fd); return -1; }
    char *p = buffer;
    unsigned long long l = (unsigned long long)length;
    if (lseek(fd, 0, SEEK_SET) < 0) {
        munmap(buffer, (size_t)length + 1);
        close(fd);
        return -1;
    }
    while (l) {
        long chk = read(fd, p, l);
        if (chk <= 0) {
            munmap(buffer, (size_t)length + 1);
            close(fd);
            return -1;
        }
        p += chk;
        l -= chk;
    }
    buffer[length] = '\0';
    close(fd);
    *ptr = buffer;
    *sz = (unsigned long long)length;
    return 0;
}

// evf_open, evf_cancel, evf_close - some events for reboot
int evf_open(char *);
void evf_cancel(int, unsigned long long, unsigned long long);
void evf_close(int);

void reboot_thread(void *_)
{
    // Wait a bit and then reboot
    const struct timespec delay = { .tv_sec = 8, .tv_nsec = 0 };
    nanosleep(&delay, NULL);
    int evf = evf_open("SceSysCoreReboot");
    evf_cancel(evf, 0x4000, 0);
    evf_close(evf);
    kill(1, SIGUSR1);
    
    // Threads must not return, so we exit or hang.
    // A return would cause user thread fatal error
    thr_exit(NULL);
    for(;;);
}

void alert(const char* msg)
{
    log_msg(msg);
}

int my_atoi(const char *s)
{
    int ret = 0, neg = 0;
    while (*s == ' ') s++;
    neg = (*s == '-') ? 1 : 0;
    if (*s == '-' || *s == '+') s++;
    for (; *s; s++) {
        char c = *s;
        if ('0' <= c && c <= '9') {
            if (ret > 1000000) return 0;
            ret *= 10; ret += c - '0';
        }
        else break;
    }
    return neg ? -ret : ret;
}

static int pack_kexec_args(int vram_mb, u16 fw_ver, int sb_val)
{
    u32 sb_family = (u32)((sb_val >> 16) & 0xF); 
    
    return (int)(
        ((sb_family & 0xF) << KEXEC_SB_SHIFT) | 
        ((u32)fw_ver << KEXEC_FW_SHIFT)       | 
        ((u32)vram_mb & KEXEC_VRAM_MASK)
    );
}

// kernel_main() — in kernel context after kexec exploit
// Reads g_fw / g_kexec_s / g_kexec_e which main() sets

void kexec(void *f, void *u);

static unsigned long long get_syscall(void)
{
    unsigned int eax, ecx, edx;
    ecx = 0xc0000082;
    asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(ecx));
    return ((unsigned long long)edx) << 32 | eax;
}

void kernel_main(void)
{
    // kernel_base calculate
    unsigned long long kernel_base = get_syscall() - g_fw->xfast_syscall;

    if (g_fw->fw_ver != 1402) {
        kernel_stage_result = 200;
        return;
    }
    kernel_stage_result = guard_1402(kernel_base);
    if (kernel_stage_result) return;

    // Disable write-protect to patch kernel
    unsigned long long saved_flags, saved_cr0, writable_cr0;
    asm volatile("pushfq; pop %0; cli; mov %%cr0, %1"
                 : "=r"(saved_flags), "=r"(saved_cr0) : : "memory");
    writable_cr0 = saved_cr0 & ~(1ULL << 16);
    asm volatile("mov %0, %%cr0" : : "r"(writable_cr0) : "memory");

    *(char *)(kernel_base + g_fw->patch1) = 0x07;
    *(char *)(kernel_base + g_fw->patch2) = 0x07;
    // pstate set before shutdown (needed for PS4 Pro)
    *(char *)(kernel_base + g_fw->pstate)  = 0x03;

    asm volatile("mov %0, %%cr0; push %1; popfq"
                 : : "r"(saved_cr0), "r"(saved_flags) : "memory");

    unsigned long long early_printf = kernel_base + g_fw->printf_off;
    unsigned long long kmem_alloc   = kernel_base + g_fw->kmem_alloc;
    unsigned long long kernel_map   = kernel_base + g_fw->kernel_map;

    // Kernel memory alloc and copy kexec blob
    char *new_kexec = ((char *(*)(unsigned long long, unsigned long long))
                       kmem_alloc)(*(unsigned long long *)kernel_map,
                                   g_kexec_e - g_kexec_s);
    if (!new_kexec) {
        kernel_stage_result = 201;
        return;
    }
    for (int i = 0; g_kexec_s + i != g_kexec_e; i++)
        new_kexec[i] = g_kexec_s[i];

    // Launch kexec blob
    kernel_stage_result = ((int (*)(void *, void *))new_kexec)((void *)early_printf, NULL);
}

// VRAM default values

#ifndef VRAM_MB_DEFAULT
#define VRAM_MB_DEFAULT 1024
#endif
#ifndef VRAM_MB_MIN
#define VRAM_MB_MIN 32
#endif
#ifndef VRAM_MB_MAX
#define VRAM_MB_MAX 4609
#endif
#ifndef HDD_BOOT_PATH
#define HDD_BOOT_PATH "/data/linux/boot/"
#endif
#ifndef HDD_SECOND_BOOT_PATH
#define HDD_SECOND_BOOT_PATH "/user/system/boot/"
#endif

int get_sb_id(void)
{
    return checked_subid();
}

const char* GetSouthbridgeName(int val) {
    // Sistro's hex patterns (0xXXYYZZ)
    switch (val & 0xFFFFFF) {
        case 0x10100: return "Aeolia A0";
        case 0x10200: return "Aeolia A1";
        case 0x10300: return "Aeolia A2";
        case 0x20100: return "Belize A0";
        case 0x20200: return "Belize B0";
        case 0x30100: return "Baikal A0";
        case 0x30200: return "Baikal B0";
        case 0x30201: return "Baikal B1";
        case 0x40100: return "Belize2 A0";
        default:      return "Unknown Southbridge";
    }
}

// main() — user-space entry pointas

int main(void)
{
    local_log_fd = open("/data/linux/portage-linux/loader.log",
                        O_CREAT | O_TRUNC | O_WRONLY, 0644);
    log_msg("PS4_1402_BELIZE2_CHECKED_LOADER_START");

    // Firmware detection and blob selection
    u16 fw_ver = get_firmware();
    log_result("FIRMWARE", fw_ver);
    u16 norm   = normalize_fw_ver(fw_ver);

    g_fw = find_offsets_by_fw(norm);
    if (!g_fw) {
        alert("AIO: Unsupported firmware version - no offset table entry.");
        return 1;
    }
    if (norm != 1402) {
        alert("This checked build requires firmware 14.02.");
        return 1;
    }

    get_kexec_blob(norm, &g_kexec_s, &g_kexec_e);
    if (!g_kexec_s || g_kexec_s == g_kexec_e) {
        alert("AIO: No kexec blob found for this firmware.");
        return 1;
    }
    // southbridge
    int sb_val = get_sb_id();
    log_result("SOUTHBRIDGE", (unsigned int)sb_val);
    if ((sb_val & 0xffffff) != 0x40100) {
        alert("This checked build requires Belize2 A0.");
        return 1;
    }

    // Linux files loading from USB or HDD
    char *kernel = NULL; unsigned long long kernel_size = 0;
    char *initrd = NULL; unsigned long long initrd_size = 0;
    char *cmdline = NULL; unsigned long long cmdline_size = 0;
    char *vramstr = NULL; unsigned long long vramstr_size = 0;
    int vram_mb = 0;

#define L(name, where, wheresz, is_fatal) \
    if (read_file(HDD_BOOT_PATH name, where, wheresz) \
     && is_fatal) { \
        alert("Failed to load file: " name "\nChecked paths:\n" \
                HDD_BOOT_PATH name); \
        return 1; \
    }

    L("bzImage",            &kernel,  &kernel_size,  1);
    L("initramfs.cpio.gz",  &initrd,  &initrd_size,  1);
    log_result("KERNEL_SIZE", kernel_size);
    log_result("INITRAMFS_SIZE", initrd_size);
    L("bootargs.txt",       &cmdline, &cmdline_size,  0);

    if (cmdline && cmdline_size) {
        for (int i = 0; i < (int)cmdline_size; i++)
            if (cmdline[i] == '\n') { cmdline[i] = '\0'; break; }
    } else {
        cmdline = "panic=0 clocksource=tsc consoleblank=0 net.ifnames=0 "
                  "radeon.dpm=0 amdgpu.dpm=0 drm.debug=0 "
                  "console=ttyS0,115200n8 console=tty0 "
                  "video=HDMI-A-1:1920x1080@60";
    }

    L("vram.txt", &vramstr, &vramstr_size, 0);
    if (vramstr && vramstr_size) {
        vram_mb = my_atoi(vramstr);
        if (vram_mb < VRAM_MB_MIN || vram_mb > VRAM_MB_MAX)
            vram_mb = VRAM_MB_DEFAULT;
    } else {
        vram_mb = VRAM_MB_DEFAULT;
    }

    if (kernel_size < 0x240 || kernel[0x1fe] != 0x55 ||
        (unsigned char)kernel[0x1ff] != 0xaa ||
        kernel[0x202] != 'H' || kernel[0x203] != 'd' ||
        kernel[0x204] != 'r' || kernel[0x205] != 'S' ||
        initrd_size < 2 || (unsigned char)initrd[0] != 0x1f ||
        (unsigned char)initrd[1] != 0x8b) {
        alert("Invalid bzImage or gzip initramfs; aborting before kernel changes.");
        return 1;
    }

    if (kernel_size != 20718592ULL || initrd_size != 12595590ULL ||
        boot_crc32(kernel, kernel_size) != 0x7fccbf20U ||
        boot_crc32(initrd, initrd_size) != 0x7b56d686U) {
        alert("Boot files differ from the verified Strawberry 7.3.3 pair; aborting before kernel changes.");
        return 1;
    }
    log_msg("BOOT_FILE_CRC32_OK");

    // Launch kernel exploit → kernel_main()
    kexec(kernel_main, (void *)0);
    log_result("KERNEL_STAGE_RESULT", (unsigned long long)kernel_stage_result);
    if (kernel_stage_result != 0) {
        alert("Kernel compatibility check or kexec initialization failed; no reboot requested.");
        return 1;
    }

    int load_result = kexec_load(kernel, kernel_size, initrd, initrd_size, cmdline,
                                pack_kexec_args(vram_mb, fw_ver, sb_val));
    log_result("KEXEC_LOAD_RESULT", (unsigned long long)load_result);
    if (load_result != 0) {
        alert("kexec_load failed; no reboot requested.");
        return 1;
    }
    log_msg("KEXEC_ARMED; normal shutdown requested in eight seconds");

    // Launch reboot watchdog thread, then Linux loader
    long x, y;
    struct thr_param thr = {
        .start_func = reboot_thread,
        .arg        = NULL,
        .stack_base = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
        .stack_size = 16384,
        .tls_base   = NULL,
        .tls_size   = 0,
        .child_tid  = &x,
        .parent_tid = &y,
        .flags      = 0,
        .rtp        = NULL,
    };
    if (thr.stack_base == MAP_FAILED || thr_new(&thr, sizeof(thr)) != 0) {
        alert("Linux is armed but automatic shutdown failed; shut down normally to continue.");
        return 1;
    }
    for (;;) {
        const struct timespec delay = { .tv_sec = 1, .tv_nsec = 0 };
        nanosleep(&delay, NULL);
    }
}

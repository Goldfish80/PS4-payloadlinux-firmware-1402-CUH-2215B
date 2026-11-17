/* Local read-only compatibility probe, intended for the owner's PS4 14.02.
 * No kernel patches, firmware calls, syscall installation or reboot here. */
#include <sys/types.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include "loader/linux/guards-1402.h"
#include "loader/linux/fw_detect.h"
#include "loader/linux/sysctl-subid.h"
extern long kexec(void *, void *);
extern int __sysctl(const int *, unsigned int, void *, size_t *, const void *, size_t);
static volatile int kernel_result = -999;
static volatile unsigned long long kernel_base_result;
static int log_fd = -1;
static unsigned char io_buffer[65536];
static void text(const char *s) {
    size_t n = 0; while (s[n]) ++n;
    while (n && log_fd >= 0) {
        long r = write(log_fd, s, n); if (r <= 0) break;
        s += r; n -= (size_t)r;
    }
}
static void hex(unsigned long long value) {
    char b[19]; const char *digits = "0123456789abcdef";
    b[0] = '0'; b[1] = 'x';
    for (int i=0; i<16; ++i) b[i+2] = digits[(value >> (60-i*4)) & 15];
    b[18] = 0; text(b);
}
static void kernel_check(void) {
    unsigned int low,high;
    __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0xc0000082));
    unsigned long long base = (((unsigned long long)high << 32) | low) - 0x1c0;
    kernel_base_result = base;
    kernel_result = guard_1402(base);
}
static unsigned int crc_update(unsigned int c, const unsigned char *p, size_t n) {
    for (size_t i=0; i<n; ++i) {
        c ^= p[i];
        for (int j=0; j<8; ++j) c = (c >> 1) ^ (0xedb88320U & (0U - (c & 1)));
    }
    return c;
}
static int inspect(const char *path) {
    int fd = open(path, O_RDONLY, 0);
    text("FILE "); text(path); text("\n");
    if (fd < 0) { text("OPEN_FAILED\n"); return 1; }
    unsigned long long total=0; unsigned int crc=0xffffffffU;
    for (;;) {
        long n = read(fd, io_buffer, sizeof(io_buffer));
        if (n < 0) { text("READ_FAILED\n"); close(fd); return 1; }
        if (!n) break;
        total += (unsigned long long)n;
        crc = crc_update(crc, io_buffer, (size_t)n);
    }
    close(fd); text("SIZE ");hex(total);text(" CRC32 ");hex(crc^0xffffffffU);text("\n");
    return 0;
}
int main(void) {
    log_fd = open("/data/linux/portage-linux/preflight.log", O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (log_fd < 0) return 91;
    text("PS4_1402_PREFLIGHT_V1\nUID ");hex(getuid());text("\n");
    unsigned int a,b,c,d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    text("CPUID_SIGNATURE ");hex(a);text("\n");
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000000U), "c"(0));
    if (a >= 0x80000004U) {
        union { unsigned int words[13]; char bytes[52]; } brand = { .words = {0} };
        for (unsigned int leaf = 0; leaf < 3; ++leaf) {
            __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000002U + leaf), "c"(0));
            brand.words[leaf*4] = a; brand.words[leaf*4+1] = b;
            brand.words[leaf*4+2] = c; brand.words[leaf*4+3] = d;
        }
        text("CPU_BRAND ");text(brand.bytes);text("\n");
    }
    unsigned long long physmem = 0; size_t physmem_size = sizeof(physmem);
    if (checked_sysctl_read("hw.physmem", 10, &physmem, &physmem_size) == 0) {
        text("HW_PHYSMEM ");hex(physmem);text("\n");
    }
    text("USER_SUBID ");hex((unsigned int)checked_subid());text("\n");
    text("SELF_FIRMWARE ");hex(get_firmware());text("\n");
    fsync(log_fd);
    long rc = kexec(kernel_check, 0);
    text("KEXEC_SYSCALL_RETURN ");hex((unsigned long long)rc);text("\nBASE ");hex(kernel_base_result);
    text("\nGUARD_RESULT ");hex((unsigned long long)kernel_result);text("\n");fsync(log_fd);
    int failures = inspect("/data/linux/boot/bzImage");fsync(log_fd);
    failures += inspect("/data/linux/boot/initramfs.cpio.gz");fsync(log_fd);
    failures += inspect("/data/linux/boot/bootargs.txt");
    text(failures == 0 && kernel_result == 0 ? "PREFLIGHT_OK\n" : "PREFLIGHT_FAILED\n");
    fsync(log_fd);close(log_fd);return failures || kernel_result != 0;
}

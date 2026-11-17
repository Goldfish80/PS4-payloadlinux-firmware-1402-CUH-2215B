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

static volatile unsigned long long __attribute__((section(".data"))) rows[2][6];
static volatile int step= -1;
static int virtual_probe(void) {
 unsigned int lo,hi;__asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(0xc0000082));
 unsigned long long base=(((unsigned long long)hi<<32)|lo)-0x1c0;
 void *map=*(void**)(base+0x22d1d50);
 unsigned long long (*allocate)(void*,unsigned long long)=(void*)(base+0x466920);
 unsigned long long (*physical)(void*,unsigned long long)=(void*)(base+0x573d0);
 void (*release)(void*,unsigned long long,unsigned long long)=(void*)(base+0x466af0);
 unsigned long long sizes[2]={0x13c4000,0xc24000};
 for(int i=0;i<2;i++){
  step=10+i;rows[i][0]=sizes[i];unsigned long long ret=allocate(map,sizes[i]);rows[i][1]=ret;
  if(ret){step=20+i;rows[i][2]=physical((void*)(base+0x1b2c3a0),ret);rows[i][3]=physical((void*)(base+0x1b2c3a0),ret+sizes[i]-0x4000);
  unsigned long long dmap=0xffff800000000000ULL|((unsigned long long)*(unsigned int*)(base+0x1b2c394)<<39)|((unsigned long long)*(unsigned int*)(base+0x1b2c398)<<30);
  rows[i][4]=physical((void*)(base+0x1b2c3a0),dmap+rows[i][2]);rows[i][5]=physical((void*)(base+0x1b2c3a0),dmap|rows[i][2]);step=30+i;release(map,ret,sizes[i]);}
 }
 step=0;return 0;
}
int main(void) {
 log_fd=open("/data/linux/portage-linux/virtual-dmap-probe.log",O_CREAT|O_TRUNC|O_WRONLY,0644);
 if(log_fd<0)return 1;text("VIRTUAL_DMAP_PROBE_V1\n");fsync(log_fd);
 for(int i=0;i<2;i++)for(int j=0;j<6;j++)rows[i][j]=0;
 long call=kexec(virtual_probe,0);text("CALL ");hex(call);text(" STEP ");hex(step);text("\n");
 for(int i=0;i<2;i++){text("SIZE ");hex(rows[i][0]);text(" VA ");hex(rows[i][1]);text(" FIRST_PA ");hex(rows[i][2]);text(" LAST_PA ");hex(rows[i][3]);text(" ADD_ALIAS_PA ");hex(rows[i][4]);text(" OR_ALIAS_PA ");hex(rows[i][5]);text("\n");}
 fsync(log_fd);close(log_fd);return step;
}

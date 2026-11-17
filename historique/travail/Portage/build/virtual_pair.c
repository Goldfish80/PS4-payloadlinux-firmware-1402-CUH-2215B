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

static volatile unsigned long long __attribute__((section(".data"))) pages[2048]={1};
static volatile unsigned long long __attribute__((section(".data"))) report[16]={1};
static unsigned long long pattern(unsigned long long i,unsigned b) {
 return 0x1402be1200000000ULL ^ (i*0x9e3779b97f4a7c15ULL) ^ ((unsigned long long)b<<48);
}
static int pair_probe(void) {
 unsigned int lo,hi;__asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(0xc0000082));
 unsigned long long base=(((unsigned long long)hi<<32)|lo)-0x1c0;
 int guard=guard_1402(base);report[0]=1;report[1]=guard;if(guard)return 0;
 void *map=*(void**)(base+0x22d1d50);
 unsigned long long (*allocate)(void*,unsigned long long)=(void*)(base+0x466920);
 unsigned long long (*physical)(void*,unsigned long long)=(void*)(base+0x573d0);
 void (*release)(void*,unsigned long long,unsigned long long)=(void*)(base+0x466af0);
 unsigned long long sizes[2]={0x13c4000,0xc24000},va[2]={0,0};
 unsigned long long dmap=0xffff800000000000ULL|((unsigned long long)*(unsigned int*)(base+0x1b2c394)<<39)|((unsigned long long)*(unsigned int*)(base+0x1b2c398)<<30);
 report[0]=2;
 for(unsigned b=0;b<2;b++){va[b]=allocate(map,sizes[b]);report[2+b]=va[b];if(!va[b])goto cleanup;}
 report[0]=3;
 unsigned n=0;
 for(unsigned b=0;b<2;b++){
  for(unsigned long long off=0;off<sizes[b];off+=0x4000){
   unsigned long long pa=physical((void*)(base+0x1b2c3a0),va[b]+off);
   if(!pa||(pa&0x3fff)||pa>=0x400000000ULL){report[4]++;goto cleanup;}
   for(unsigned j=0;j<n;j++)if(pages[j]==pa){report[5]++;goto cleanup;}
   if(n>=2048){report[4]++;goto cleanup;}pages[n++]=pa;
   if(pa>=0x100000000ULL)report[6]++;
   if(physical((void*)(base+0x1b2c3a0),dmap+pa)!=pa)report[7]++;
   if(physical((void*)(base+0x1b2c3a0),dmap|pa)!=pa)report[8]++;
  }
  volatile unsigned long long *buf=(void*)va[b];
  for(unsigned long long i=0;i<sizes[b]/8;i++)buf[i]=pattern(i,b);
 }
 report[9]=n;report[0]=4;
 /* Verify both only after all writes, detecting aliasing between allocations. */
 for(unsigned b=0;b<2;b++){
  volatile unsigned long long *buf=(void*)va[b];
  for(unsigned long long i=0;i<sizes[b]/8;i++)if(buf[i]!=pattern(i,b))report[10]++;
  report[11]+=sizes[b];
 }
 report[0]=5;
cleanup:
 for(int b=1;b>=0;b--)if(va[b]){release(map,va[b],sizes[b]);report[12]++;}
 return 0;
}
int main(void) {
 log_fd=open("/data/linux/portage-linux/virtual-pair-probe.log",O_CREAT|O_TRUNC|O_WRONLY,0644);
 if(log_fd<0)return 1;
 for(unsigned i=0;i<2048;i++)pages[i]=0;
 for(unsigned i=0;i<16;i++)report[i]=0;
 text("VIRTUAL_PAIR_V1\n");fsync(log_fd);
 long rc=kexec(pair_probe,0);text("CALL ");hex(rc);text("\n");
 const char *labels[]={"STAGE","GUARD","KERNEL_VA","INITRD_VA","INVALID_PA","DUPLICATE_PA","HIGH_PA_PAGES","ADD_ALIAS_MISMATCH","OR_ALIAS_MISMATCH","PAGES","CONTENT_ERRORS","BYTES_VERIFIED","FREES"};
 for(unsigned i=0;i<13;i++){text(labels[i]);text(" ");hex(report[i]);text("\n");}
 for(unsigned i=0;i<report[9]&&i<2048;i++){text("PAGE ");hex(i);text(" ");hex(pages[i]);text("\n");}
 text(rc==0&&report[0]==5&&!report[4]&&!report[5]&&!report[7]&&!report[10]&&report[12]==2?"PAIR_PASS\n":"PAIR_FAILED\n");
 fsync(log_fd);close(log_fd);return 0;
}

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

struct result_t { unsigned long long size, flags, mapped, physical, code; };
static volatile struct result_t allocation_results[10] __attribute__((section(".data"))) = {{0}};
static volatile unsigned long long __attribute__((section(".data"))) control_physical, pmap_root, physmem_pages, realmem_pages;
static volatile int maintenance_result=-999;
static const unsigned char old_slot[48] = { 0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xa0,0x47,0x2d,0xc7,0xff,0xff,0xff,0xff,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x4,0x0,0x0,0x0 };
static const unsigned char owner_head[64] = { 0x41,0x55,0x41,0x54,0x49,0x89,0xf5,0x55,0x53,0x51,0x9c,0x41,0x5c,0xfa,0xf,0x20,0xc3,0x48,0x89,0xd8,0x48,0x25,0xff,0xff,0xfe,0xff,0xf,0x22,0xc0,0xe8,0xe2,0x25,0x0,0x0,0xbd,0xff,0xff,0xff,0xff,0x85,0xc0,0x78,0x4f,0xbe,0x99,0x0,0x0,0x0,0x48,0x8d,0x3d,0x9,0x32,0x0,0x0,0x31,0xc0,0xff,0x15,0x51,0x3a,0x0,0x0,0xba };
static int maintenance(void) {
 unsigned int lo,hi;
 __asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(0xc0000082));
 unsigned long long base=(((unsigned long long)hi<<32)|lo)-0x1c0;
 if(base!=0xffffffffc7114000ULL){maintenance_result=1;return 0;}
 if (*(volatile unsigned long long*)(base+0x1102b70+153*48+8)!=0xffffffffc72d47a0ULL){maintenance_result=2;return 0;}
 if(0x0ULL) {
  for(int i=0;i<64;i++) if(*(volatile unsigned char*)(0x0ULL+i)!=owner_head[i]){maintenance_result=3;return 0;}
  unsigned long long f,cr,wr;
  __asm__ volatile("pushfq;pop %0;cli;mov %%cr0,%1":"=r"(f),"=r"(cr)::"memory");
  wr=cr&~(1ULL<<16);__asm__ volatile("mov %0,%%cr0"::"r"(wr):"memory");
  for(int i=0;i<48;i++)*(volatile unsigned char*)(base+0x1102b70+153*48+i)=old_slot[i];
  __asm__ volatile("mov %0,%%cr0;push %1;popfq"::"r"(cr),"r"(f):"memory");
  ((void(*)(void*,unsigned long long,unsigned long long))(base+0x466af0))(*(void**)(base+0x22d1d50),0x0ULL,15364ULL);
 }
 maintenance_result=10;
 pmap_root=*(volatile unsigned long long*)(base+0x1b2c3a0+0x20);
 physmem_pages=*(volatile unsigned long long*)(base+0x22cf660);
 realmem_pages=*(volatile unsigned long long*)(base+0x21ad368);
 maintenance_result=11;
 if((pmap_root>>48)!=0xffff){maintenance_result=4;return 0;}
 unsigned long long (*extract)(void*,unsigned long long)=(void*)(base+0x573d0);
 control_physical=extract((void*)(base+0x1b2c3a0),base);maintenance_result=12;
 unsigned long long sizes[10]={0x4000,0x10000,0x100000,0x13c2400,0xc231f6,0x4000,0x10000,0x100000,0x13c2400,0xc231f6};
 unsigned long long (*allocate)(void*,unsigned long long,int,unsigned long long,unsigned long long,unsigned long,unsigned long,char)=(void*)(base+0x24dbe0);
 void (*release)(void*,unsigned long long,unsigned long long)=(void*)(base+0x466af0);
 for(int i=0;i<10;i++) {
  maintenance_result=20+i;allocation_results[i].size=sizes[i];allocation_results[i].flags=i<5?0x101:0x102;
  unsigned long long ret=allocate(*(void**)(base+0x22d1d50),sizes[i],(int)allocation_results[i].flags,0,~0ULL,1,0,6);
  allocation_results[i].mapped=ret;
  if(ret){maintenance_result=30+i;allocation_results[i].physical=extract((void*)(base+0x1b2c3a0),ret);maintenance_result=40+i;release(*(void**)(base+0x22d1d50),ret,sizes[i]);}maintenance_result=50+i;
 }
 maintenance_result=0;return 0;
}
int main(void) {
 log_fd=open("/data/linux/portage-linux/allocator-probe.log",O_CREAT|O_TRUNC|O_WRONLY,0644);
 if(log_fd<0)return 1;text("ALLOCATOR_PROBE_V1\n");fsync(log_fd);
 pmap_root=0;control_physical=0;physmem_pages=0;realmem_pages=0;
 for(int i=0;i<10;i++){allocation_results[i].size=0;allocation_results[i].mapped=0;allocation_results[i].physical=0;}
 long call=kexec(maintenance,0);text("CALL ");hex(call);text(" RESULT ");hex(maintenance_result);text("\nROOT ");hex(pmap_root);
 text(" CONTROL_PHYSICAL ");hex(control_physical);text("\nPHYSMEM_PAGES ");hex(physmem_pages);text(" REALMEM_PAGES ");hex(realmem_pages);text("\n");fsync(log_fd);
 for(int i=0;i<10;i++){
  text("SIZE ");hex(allocation_results[i].size);text(" FLAGS ");hex(allocation_results[i].flags);text(" MAPPED ");hex(allocation_results[i].mapped);text(" PHYSICAL ");hex(allocation_results[i].physical);text("\n");
 }
 fsync(log_fd);close(log_fd);return maintenance_result;
}

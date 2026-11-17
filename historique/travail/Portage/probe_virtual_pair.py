#!/usr/bin/env python3
"""Bounded simultaneous allocation/content test; no handoff or kernel patch."""
from pathlib import Path
import subprocess,json
from ps4_transport import Debug
from portage_linux import select_target
ROOT=Path(__file__).resolve().parent
source=(ROOT/'preflight.c').read_text().split('int main(void)')[0]+r'''
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
'''
p=ROOT/'build/virtual_pair.c';p.write_text(source)
flags=['-I'+str(ROOT),'-isystem',str(ROOT/'loader/freebsd-headers'),'-nostdinc','-nostdlib','-fno-stack-protector','-fno-asynchronous-unwind-tables','-static','-fPIE','-ffreestanding','-mno-red-zone','-mno-sse','-mno-sse2','-mno-mmx']
subprocess.run(['cc',*flags,str(ROOT/'loader/lib/lib.a'),str(p),'-Wl,--gc-sections,--build-id=none,-Ttext-segment=0','-o',str(ROOT/'build/virtual_pair.elf')],check=True)
c=Debug(timeout=20)
if c.firmware()!=1402:raise RuntimeError('Wrong firmware')
t=select_target(c);c.elf(t['pid'],(ROOT/'build/virtual_pair.elf').read_bytes());print('Simultaneous virtual-allocation probe sent',t,flush=True)

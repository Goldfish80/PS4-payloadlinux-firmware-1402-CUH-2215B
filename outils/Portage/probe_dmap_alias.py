#!/usr/bin/env python3
from pathlib import Path
import sys,subprocess
from ps4_transport import Debug
ROOT=Path(__file__).resolve().parent
s=(ROOT/'preflight.c').read_text().split('int main(void)')[0]
s+=r'''
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
'''
p=ROOT/'build/virtual_allocator.c';p.write_text(s)
flags=['-I'+str(ROOT),'-isystem',str(ROOT/'loader/freebsd-headers'),'-nostdinc','-nostdlib','-fno-stack-protector','-fno-asynchronous-unwind-tables','-static','-fPIE','-ffreestanding','-mno-red-zone','-mno-sse','-mno-sse2','-mno-mmx']
subprocess.run(['cc',*flags,str(ROOT/'loader/lib/lib.a'),str(p),'-Wl,--gc-sections,--build-id=none,-Ttext-segment=0','-o',str(ROOT/'build/virtual_allocator.elf')],check=True)
from portage_linux import select_target
c=Debug(timeout=20);t=select_target(c);c.elf(t['pid'],(ROOT/'build/virtual_allocator.elf').read_bytes());print('Virtual-allocation probe sent',t,flush=True)

#!/usr/bin/env python3
"""Restore only our unused syscall handler, then probe bounded allocations.
No Linux handoff, firmware calls, or reboot in this diagnostic payload.
"""
from pathlib import Path
import sys,struct,json,subprocess
from ps4_transport import Debug
ROOT=Path(__file__).resolve().parent;OUT=ROOT.parent.parent/'portage-linux/recherche'
c=Debug(timeout=20);base=c.base();slot=base+0x1102b70+153*48;current=c.kernel(slot,48);handler=struct.unpack_from('<Q',current,8)[0];blob=(ROOT/'loader/linux/kexec-build/1402/kexec.bin').read_bytes()
symbols=subprocess.check_output(['nm','-n',str(ROOT/'loader/linux/kexec-build/1402/kexec.elf')],text=True);offset=int(next(x.split()[0] for x in symbols.splitlines() if x.split()[-1]=='sys_kexec'),16)
owner=0
if handler!=base+0x1c07a0:
 owner=handler-offset
 if c.kernel(owner,64)!=blob[:64]:raise RuntimeError('Syscall 153 is not owned by the checked payload; refusing restoration')
original=bytearray.fromhex(json.loads((OUT/'syscall_slots.json').read_text())['153']['hex']);struct.pack_into('<Q',original,8,base+0x1c07a0)
source=(ROOT/'preflight.c').read_text();source=source[:source.index('int main(void)')]
extra=r'''
struct result_t { unsigned long long size, flags, mapped, physical, code; };
static volatile struct result_t allocation_results[10] __attribute__((section(".data"))) = {{0}};
static volatile unsigned long long __attribute__((section(".data"))) control_physical, pmap_root, physmem_pages, realmem_pages;
static volatile int maintenance_result=-999;
static const unsigned char old_slot[48] = { ORIGINAL };
static const unsigned char owner_head[64] = { HEAD };
static int maintenance(void) {
 unsigned int lo,hi;
 __asm__ volatile("rdmsr":"=a"(lo),"=d"(hi):"c"(0xc0000082));
 unsigned long long base=(((unsigned long long)hi<<32)|lo)-0x1c0;
 if(base!=BASE){maintenance_result=1;return 0;}
 if (*(volatile unsigned long long*)(base+0x1102b70+153*48+8)!=HANDLER){maintenance_result=2;return 0;}
 if(OWNER) {
  for(int i=0;i<64;i++) if(*(volatile unsigned char*)(OWNER+i)!=owner_head[i]){maintenance_result=3;return 0;}
  unsigned long long f,cr,wr;
  __asm__ volatile("pushfq;pop %0;cli;mov %%cr0,%1":"=r"(f),"=r"(cr)::"memory");
  wr=cr&~(1ULL<<16);__asm__ volatile("mov %0,%%cr0"::"r"(wr):"memory");
  for(int i=0;i<48;i++)*(volatile unsigned char*)(base+0x1102b70+153*48+i)=old_slot[i];
  __asm__ volatile("mov %0,%%cr0;push %1;popfq"::"r"(cr),"r"(f):"memory");
  ((void(*)(void*,unsigned long long,unsigned long long))(base+0x466af0))(*(void**)(base+0x22d1d50),OWNER,BLOBSIZE);
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
'''
for key,val in {'ORIGINAL':','.join(hex(x) for x in original),'HEAD':','.join(hex(x) for x in blob[:64]),'BASE':hex(base)+'ULL','HANDLER':hex(handler)+'ULL','OWNER':hex(owner)+'ULL','BLOBSIZE':str(len(blob))+'ULL'}.items():extra=extra.replace(key,val)
p=ROOT/'build/allocator_probe.c';p.write_text(source+extra)
flags=['-I'+str(ROOT),'-isystem',str(ROOT/'loader/freebsd-headers'),'-nostdinc','-nostdlib','-fno-stack-protector','-fno-asynchronous-unwind-tables','-static','-fPIE','-ffreestanding','-mno-red-zone','-mno-sse','-mno-sse2','-mno-mmx']
subprocess.run(['cc',*flags,str(ROOT/'loader/lib/lib.a'),str(p),'-Wl,--gc-sections,--build-id=none,-Ttext-segment=0','-o',str(ROOT/'build/allocator_probe.elf')],check=True)
from portage_linux import select_target
t=select_target(c);c.elf(t['pid'],(ROOT/'build/allocator_probe.elf').read_bytes());print('Maintenance/probe sent',{'target':t,'owned_blob':hex(owner),'size':len(blob)},flush=True)
(OUT/'allocator_probe_plan.json').write_text(json.dumps({'base':hex(base),'handler':hex(handler),'owned_blob':hex(owner),'blob_size':len(blob),'restore_to':original.hex(),'no_reboot':True},indent=2))

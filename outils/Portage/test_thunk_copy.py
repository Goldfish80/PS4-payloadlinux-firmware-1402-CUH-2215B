#!/usr/bin/env python3
"""Execute the compiled REP copy loop in user mode, excluding privileged setup."""
from pathlib import Path
import ctypes as c,mmap,struct,subprocess
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
ROOT=Path(__file__).resolve().parent
with (ROOT/'loader/linux/kexec-build/1402/kexec.elf').open('rb') as f:
 elf=ELFFile(f);sym=elf.get_section_by_name('.symtab').get_symbol_by_name('jmp_to_linux')[0];addr=sym['st_value'];sec=elf.get_section(sym['st_shndx']);blob=sec.data()[addr-sec['sh_addr']:addr-sec['sh_addr']+256]
ins=list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(blob,0))
start=next(i.address+i.size for i in ins if i.mnemonic=='mov' and i.op_str=='cr3, rdx')
end=next(i.address for i in ins if i.mnemonic=='mov' and i.op_str=='rdi, 0x6000000')
loop=blob[start:end]
assert len(loop)<128 and b'\xf3\x48\xa5' in loop
# Preserve host callee-saved regs, translate SysV args into the thunk's R8/R9.
wrapper=bytes.fromhex('415441554989f84989f1')+loop+bytes.fromhex('415d415cc3')
code=mmap.mmap(-1,4096,prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);code.write(wrapper)
run=c.CFUNCTYPE(None,c.c_uint64,c.c_uint64)(c.addressof(c.c_char.from_buffer(code)))
libc=c.CDLL(None,use_errno=True);libc.mmap.restype=c.c_void_p;libc.mmap.argtypes=[c.c_void_p,c.c_size_t,c.c_int,c.c_int,c.c_int,c.c_long];libc.munmap.argtypes=[c.c_void_p,c.c_size_t]
regions=[]
def region(pa,n):
 p=libc.mmap(pa,n,3,0x100022,-1,0)
 if p!=pa:raise OSError(c.get_errno(),'MAP_FIXED_NOREPLACE failed',hex(pa))
 regions.append((p,n));return p
class Move(c.Structure):_fields_=[('src',c.c_ulonglong),('dst',c.c_ulonglong)]
subprocess.run(['cc','-O2','-shared','-fPIC',str(ROOT/'loader/linux/ps4-kexec-common/reloc_plan.c'),'-o',str(ROOT/'build/reloc_plan_host.so')],check=True)
planner=c.CDLL(str(ROOT/'build/reloc_plan_host.so')).reloc_plan_build;planner.argtypes=[c.POINTER(Move),c.c_uint,c.POINTER(Move),c.c_uint,c.c_ulonglong];planner.restype=c.c_int
P=0x4000;n0=0x13c4000//P;n1=0xc24000//P;n=n0+n1
try:
 src=region(0x240000000,n*P);d0=region(0x6000000,n0*P);d1=region(0x20000000,n1*P);scratch=region(0x28000000,P)
 pending=(Move*n)();out=(Move*(2*n))()
 for i in range(n):
  pattern=struct.pack('<Q',0x1402be0000000000+i)*(P//8);c.memmove(src+i*P,pattern,P)
  pending[i]=Move(src+i*P,d0+i*P if i<n0 else d1+(i-n0)*P)
 count=planner(pending,n,out,2*n,scratch);assert count==n
 run(c.addressof(out),count)
 for i in range(n):
  dest=d0+i*P if i<n0 else d1+(i-n0)*P
  assert c.string_at(dest,P)==struct.pack('<Q',0x1402be0000000000+i)*(P//8)
 # Actual loop with dependency cycles among high-address pages.
 for cycle in [2,3,64]:
  pending=(Move*cycle)();out=(Move*(cycle*2))()
  for i in range(cycle):c.memset(src+i*P,i+1,P);pending[i]=Move(src+i*P,src+((i+1)%cycle)*P)
  count=planner(pending,cycle,out,cycle*2,scratch);assert count>0;run(c.addressof(out),count)
  for i in range(cycle):assert c.string_at(src+((i+1)%cycle)*P,P)==bytes([i+1])*P
 run(0,0)
 print('PASS: actual compiled thunk copy loop; 2042 pages / 33456128 bytes from >4 GiB; complete content verified; 2/3/64-page cycles and zero moves')
finally:
 for p,nbytes in reversed(regions):libc.munmap(p,nbytes)

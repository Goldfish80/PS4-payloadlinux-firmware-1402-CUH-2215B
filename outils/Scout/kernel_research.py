#!/usr/bin/env python3
"""Index statique d'appels/RIP du dump utilisateur ; noms toujours à confirmer."""
from pathlib import Path
import re,struct,json,bisect,sqlite3,time
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
ROOT=Path(__file__).resolve().parents[1];OUT=Path('/project/PS4/portage-linux/recherche');OUT.mkdir(exist_ok=True)
DATA=(ROOT/'reports/kernel_20261115_full.elf').read_bytes();BASE=struct.unpack_from('<Q',DATA,64+2*56+16)[0]
segments=[]
for i in range(struct.unpack_from('<H',DATA,56)[0]):
 t,flags,o,v,p,fs,ms,a=struct.unpack_from('<IIQQQQQQ',DATA,64+56*i)
 if t in (1,0x61000010):segments.append((v-BASE,o,fs,ms,flags))
def offset(rva,n=1):
 for r,o,s,m,f in segments:
  if r<=rva and rva+n<=r+s:return o+rva-r
 return None
def raw(rva,n):
 o=offset(rva,n)
 return DATA[o:o+n] if o is not None else b''
def string(rva):
 o=offset(rva)
 if o is None:return ''
 b=DATA[o:o+512].split(b'\0')[0]
 return b.decode('ascii') if b and all(32<=v<127 or v in (9,10,13) for v in b) else ''
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True
starts=[m.start() for m in re.finditer(b'\x55\x48\x89\xe5',DATA[:0x770000]) if m.start()%16==0]
def owner(rva):
 i=bisect.bisect_right(starts,rva)-1
 return starts[i] if i>=0 else None
def disasm(rva,size=256):return list(md.disasm(raw(rva,size),rva))
def show(rva,size=256):
 for i in disasm(rva,size):
  extra=[]
  for op in i.operands:
   if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:
    target=i.address+i.size+op.mem.disp;extra.append(hex(target)+' '+repr(string(target)))
  print(f'{i.address:08x} {i.bytes.hex():24s} {i.mnemonic:8s} {i.op_str:42s} '+ ' '.join(extra))
def build():
 p=OUT/'kernel_index.sqlite';db=sqlite3.connect(p);db.executescript('DROP TABLE IF EXISTS refs; DROP TABLE IF EXISTS functions; CREATE TABLE refs(pc INTEGER,owner INTEGER,kind TEXT,target INTEGER,mnemonic TEXT,op_str TEXT);CREATE TABLE functions(start INTEGER PRIMARY KEY,end INTEGER);')
 t=time.monotonic();refs=[]
 for index,start in enumerate(starts):
  end=starts[index+1] if index+1<len(starts) else 0x770000
  db.execute('INSERT INTO functions VALUES (?,?)',(start,end))
  for i in md.disasm(DATA[start:end],start):
   for op in i.operands:
    if op.type==X86_OP_MEM and op.mem.base==X86_REG_RIP:refs.append((i.address,start,'rip',i.address+i.size+op.mem.disp,i.mnemonic,i.op_str))
    elif op.type==X86_OP_IMM and i.mnemonic in ('call','jmp'):refs.append((i.address,start,i.mnemonic,op.imm,i.mnemonic,i.op_str))
  if len(refs)>10000:db.executemany('INSERT INTO refs VALUES (?,?,?,?,?,?)',refs);refs=[]
  if index%4000==0:print(index,len(starts),round(time.monotonic()-t,1),flush=True)
 db.executemany('INSERT INTO refs VALUES (?,?,?,?,?,?)',refs);db.executescript('CREATE INDEX refs_target ON refs(target);CREATE INDEX refs_owner ON refs(owner);');db.commit();print('index',p,'functions',len(starts),'seconds',time.monotonic()-t,flush=True)
if __name__=='__main__':
 import sys
 if len(sys.argv)>1:show(int(sys.argv[1],0),int(sys.argv[2],0) if len(sys.argv)>2 else 256)
 else:build()

#!/usr/bin/env python3
import socket,struct,json,re,hashlib,time
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
OUT=Path('/project/PS4/portage-linux/recherche');ROOT=Path(__file__).resolve().parents[1]
def exact(s,n):
 b=b''
 while len(b)<n:
  v=s.recv(n-len(b))
  if not v:raise EOFError(f'{len(b)}/{n}')
  b+=v
 return b
def command(c,body=b'',n=8):
 with socket.create_connection(('192.0.2.10',744),timeout=5) as s:
  s.settimeout(6);s.sendall(struct.pack('<III',0xFFAABBCC,c,len(body))+body)
  st=struct.unpack('<I',exact(s,4))[0]
  if st!=0x80000000:raise RuntimeError(hex(st))
  return exact(s,n)
def read(addr,n):return command(0xBDCC0002,struct.pack('<QI',addr,n),n)
def main():
 base=struct.unpack('<Q',command(0xBDCC0001))[0]
 d=(ROOT/'reports/kernel_20261115_full.elf').read_bytes();dbase=struct.unpack_from('<Q',d,64+2*56+16)[0]
 segs=[]
 for i in range(struct.unpack_from('<H',d,56)[0]):
  typ,flags,off,va,_,fs,ms,align=struct.unpack_from('<IIQQQQQQ',d,64+i*56)
  if typ in (1,0x61000010):segs.append((va-dbase,off,fs,ms,flags))
 def local(rva,n):
  for start,off,fs,ms,flags in segs:
   if start<=rva and rva+n<=start+fs:return d[off+rva-start:off+rva-start+n]
  return None
 t=(OUT/'magic_1402_upstream.h').read_text().split('#elif defined PS4_14_02')[1].split('#endif')[0]
 md=Cs(CS_ARCH_X86,CS_MODE_64)
 globals={'kernel_map':8,'sysent':32,'kernel_pmap_store':64,'pml4pml4i':4,'dmpml4i':4,'dmpdpi':4,'edid':256}
 m={'timestamp':datetime.now(timezone.utc).isoformat(),'base_live':hex(base),'dump_base':hex(dbase),'source':'https://github.com/jclass/ps4-linux-loader/blob/master/linux/magic.h','offsets':[]}
 for name,value in re.findall(r'#define kern_off_(\w+)\s+(0x[\da-fA-F]+)',t):
  rva=int(value,16);row={'name':name,'rva':hex(rva),'address':hex(base+rva),'source_attribution':'ArabPixel / PS4_14_02 table; role not proven merely by matching bytes'}
  if not rva:row['status']='optional_absent_in_upstream'
  elif name=='eap_hdd_key':row['status']='not_read_personal_disk_key_not_required_for_USB_boot'
  else:
   n=globals.get(name,96);b=local(rva,n)
   row['dump_backed']=b is not None
   if b is not None:row['dump_hex']=b.hex()
   if name not in globals:row['dump_disassembly']=[{'rva':hex(i.address),'bytes':i.bytes.hex(),'op':i.mnemonic+' '+i.op_str} for i in md.disasm(b or b'',rva)]
   for attempt in range(3):
    try:
     live=read(base+rva,n);row['live_hex']=live.hex();row['live_sha256']=hashlib.sha256(live).hexdigest();row['matches_dump']=live==b if b is not None else None;row['status']='read_live';break
    except Exception as e:row['error']=repr(e)
   if row.get('status')=='read_live':row.pop('error',None)
  m['offsets'].append(row);(OUT/'linux1402_verification.json').write_text(json.dumps(m,indent=2));print(name,row.get('matches_dump',row.get('status',row.get('error'))),flush=True)
 for name,rva,n in [('gpu_identification_globals',0x23889a0,16)]:
  try:m[name]={'rva':hex(rva),'live_hex':read(base+rva,n).hex()}
  except Exception as e:m[name]={'error':repr(e)}
 (OUT/'linux1402_verification.json').write_text(json.dumps(m,indent=2))
if __name__=='__main__':main()

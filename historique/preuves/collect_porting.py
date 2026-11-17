#!/usr/bin/env python3
import socket,struct,json,re,hashlib,csv,io,time
from pathlib import Path
from ftplib import FTP
from datetime import datetime,timezone
ROOT=Path('/project/PS4/Linux'); OUT=Path('/project/PS4/portage-linux');OUT.mkdir(exist_ok=True)
meta={'timestamp':datetime.now(timezone.utc).isoformat(),'ip':'192.0.2.10','debug_port':744,'ftp_port':2121,'errors':[]}
def exact(s,n):
 b=b''
 while len(b)<n:
  v=s.recv(n-len(b))
  if not v:raise EOFError()
  b+=v
 return b
def cmd(c,body=b'',n=0,status=True):
 with socket.create_connection((meta['ip'],744),timeout=5) as s:
  s.settimeout(8);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
  s.sendall(struct.pack('<III',0xFFAABBCC,c,len(body))+body)
  if status:
   st=struct.unpack('<I',exact(s,4))[0]
   if st!=0x80000000:raise RuntimeError(hex(st))
  return exact(s,n)
def read(a,n):return cmd(0xBDCC0002,struct.pack('<QI',a,n),n)
base=struct.unpack('<Q',cmd(0xBDCC0001,n=8))[0];meta['live_base']=hex(base)
meta['firmware_raw']=struct.unpack('<H',cmd(0xBD000500,n=2,status=False))[0]
data=(ROOT/'Scout/reports/kernel_20261115_full.elf').read_bytes();meta['dump_sha256']=hashlib.sha256(data).hexdigest()
try:
 head=read(base,4096);(OUT/'live_kernel_head.bin').write_bytes(head);meta['live_head_matches_dump']=head==data[:4096]
except Exception as e:meta['errors'].append('head: '+repr(e))
source=(ROOT/'Scout/upstream/ps4debug-NG/ps4-ksdk/source/ksdk.c').read_text();section=source.split('static int init_1402sdk(')[1].split('int init_ksdk(')[0]
guards={int(off,16):(name,bytes(int(x,16) for x in re.findall(r'0x[0-9A-Fa-f]+',bs))) for off,bs,name in re.findall(r'\{\s*(0x[0-9A-Fa-f]+),\s*\{([^}]+)\}\s*\},\s*/\*\s*(.*?)\s*\*/',section)}
rows=[]
for name,off in re.findall(r'(\w+)\s*=\s*\(void\s*\*\)\(kbase\s*\+\s*(0x[0-9A-Fa-f]+)\)',section):
 rva=int(off,16);row={'name':name,'rva':hex(rva),'live_address':hex(base+rva),'provenance':'ps4debug-NG init_1402sdk (nom attribue par source)','semantic_validation':'non demontree par signature seule'}
 # Translate using actual ELF segments, never assume file offset == RVA.
 for i in range(struct.unpack_from('<H',data,56)[0]):
  typ,flags,fo,va,pa,fs,ms,al=struct.unpack_from('<IIQQQQQQ',data,64+i*56)
  delta=base+rva-va
  if typ in (1,0x61000010) and 0<=delta and delta+8<=fs:
   row['file_offset']=hex(fo+delta);row['dump_bytes']=data[fo+delta:fo+delta+8].hex();break
 try:
  b=read(base+rva,8);row['live_bytes']=b.hex();row['live_matches_dump']=row.get('dump_bytes')==b.hex()
  if rva in guards:row['guard_matches_live']=b==guards[rva][1];row['guard_matches_dump']=row.get('dump_bytes')==guards[rva][1].hex()
 except Exception as e:row['error']=repr(e)
 rows.append(row);print(name,row.get('guard_matches_live',row.get('live_bytes')),flush=True)
meta['offsets']=rows
(OUT/'collection.json').write_text(json.dumps(meta,indent=2))
f=FTP();f.connect(meta['ip'],2121,timeout=8);f.login();f.set_pasv(True)
listing={}
for p in ['/','/data/linux','/data/linux/boot','/data/payloads','/system/sys','/system/priv','/mnt/usb0','/dev']:
 try:listing[p]=f.nlst(p)
 except Exception as e:listing[p]={'error':repr(e)}
(OUT/'ftp_inventory.json').write_text(json.dumps(listing,indent=2))
for p in ['/data/linux/boot/bootargs.txt','/data/linux/boot/kernel.info','/data/linux/bootargs.txt','/data/rpi_nextgen_boot.txt','/data/rpi_nextgen_crash.txt','/data/Loader_Logs.txt']:
 try:
  b=io.BytesIO();f.retrbinary('RETR '+p,b.write);(OUT/('console_'+p.replace('/','_'))).write_bytes(b.getvalue())
 except Exception as e:meta['errors'].append(p+': '+repr(e))
f.quit();(OUT/'collection.json').write_text(json.dumps(meta,indent=2));print(OUT)

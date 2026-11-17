#!/usr/bin/env python3
"""Client ps4debug-NG pour cette console ; aucune adresse absolue persistée."""
import socket,struct,time
MAGIC=0xFFAABBCC;SUCCESS=0x80000000
class Debug:
 def __init__(self,ip='192.0.2.10',port=744,timeout=10):self.ip=ip;self.port=port;self.timeout=timeout
 def connect(self):
  s=socket.create_connection((self.ip,self.port),timeout=self.timeout);s.settimeout(self.timeout);s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1);return s
 @staticmethod
 def exact(s,n):
  b=bytearray()
  while len(b)<n:
   q=s.recv(n-len(b))
   if not q:raise EOFError(f'{len(b)}/{n}')
   b.extend(q)
  return bytes(b)
 def send(self,s,cmd,body=b''):s.sendall(struct.pack('<III',MAGIC,cmd,len(body))+body)
 def status(self,s):
  v=struct.unpack('<I',self.exact(s,4))[0]
  if v!=SUCCESS:raise RuntimeError(f'ps4debug status {v:#x}')
 def fixed(self,cmd,body=b'',n=0,status=True):
  with self.connect() as s:
   self.send(s,cmd,body)
   if status:self.status(s)
   return self.exact(s,n)
 def base(self):return struct.unpack('<Q',self.fixed(0xBDCC0001,n=8))[0]
 def firmware(self):return struct.unpack('<H',self.fixed(0xBD000500,n=2,status=False))[0]
 def kernel(self,addr,n):return self.fixed(0xBDCC0002,struct.pack('<QI',addr,n),n)
 def processes(self):
  with self.connect() as s:
   self.send(s,0xBDAA0001);self.status(s);n=struct.unpack('<I',self.exact(s,4))[0]
   if n>4096:raise ValueError('process list too large')
   b=self.exact(s,n*36)
  return [dict(name=b[i*36:i*36+32].split(b'\0')[0].decode('utf-8','replace'),pid=struct.unpack_from('<I',b,i*36+32)[0]) for i in range(n)]
 def maps(self,pid):
  with self.connect() as s:
   self.send(s,0xBDAA0004,struct.pack('<I',pid));self.status(s);n=struct.unpack('<I',self.exact(s,4))[0]
   if n>100000:raise ValueError('maps too large')
   b=self.exact(s,58*n)
  return [dict(name=b[i*58:i*58+32].split(b'\0')[0].decode('utf-8','replace'),start=struct.unpack_from('<Q',b,i*58+32)[0],end=struct.unpack_from('<Q',b,i*58+40)[0],offset=struct.unpack_from('<Q',b,i*58+48)[0],prot=struct.unpack_from('<H',b,i*58+56)[0]) for i in range(n)]
 def process_read(self,pid,addr,n):return self.fixed(0xBDAA0002,struct.pack('<IQI',pid,addr,n),n)
 def elf(self,pid,data):
  if data[:6]!=b'\x7fELF\x02\x01':raise ValueError('Expected ELF64 little endian')
  with self.connect() as s:
   self.send(s,0xBDAA0007,struct.pack('<II',pid,len(data)));self.status(s)
   # Mutating requests are never retried automatically: avoid double execution.
   s.sendall(data);self.status(s)

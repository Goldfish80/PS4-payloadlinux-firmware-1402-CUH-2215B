#!/usr/bin/env python3
import sys,json,struct,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import verify_linux1402 as v
out=v.OUT/'acpi';out.mkdir(exist_ok=True)
m=json.loads((v.OUT/'linux1402_verification.json').read_text());vals={r['name']:r for r in m['offsets']};l4=int.from_bytes(bytes.fromhex(vals['dmpml4i']['live_hex']),'little');l3=int.from_bytes(bytes.fromhex(vals['dmpdpi']['live_hex']),'little');dmap=0xffff800000000000|(l4<<39)|(l3<<30)
result={'dmap_base':hex(dmap),'l4':l4,'l3':l3,'tables':[],'errors':[]}
def physical(a,n):
 if a<0 or a+n>0x100000000:raise ValueError('physical range outside first 4GiB')
 b=b''
 while len(b)<n:b+=v.read(dmap+a+len(b),min(1024,n-len(b)))
 return b
def save_table(pa):
 h=physical(pa,36);sig=h[:4].decode('ascii','replace');n=struct.unpack_from('<I',h,4)[0]
 if not all(32<=x<127 for x in h[:4]) or not 36<=n<=262144:raise ValueError(f'invalid ACPI header {hex(pa)} {h.hex()}')
 b=physical(pa,n);name=f'{sig}_{pa:x}.bin';(out/name).write_bytes(b)
 row={'signature':sig,'physical':hex(pa),'size':n,'revision':b[8],'checksum_valid':sum(b)%256==0,'oemid':b[10:16].decode('ascii','replace'),'oem_table_id':b[16:24].decode('ascii','replace'),'file':name,'sha256':hashlib.sha256(b).hexdigest()};result['tables'].append(row);print(row,flush=True);(out/'summary.json').write_text(json.dumps(result,indent=2));return b
try:
 r=physical(0xe0000,36)
 if r[:8]!=b'RSD PTR ':raise ValueError('RSDP not at expected 0xe0000: '+r.hex())
 result['rsdp']={'physical':'0xe0000','hex':r.hex(),'checksum_v1_valid':sum(r[:20])%256==0,'checksum_extended_valid':sum(r)%256==0,'revision':r[15]};(out/'RSDP_e0000.bin').write_bytes(r)
 rsdt=struct.unpack_from('<I',r,16)[0];xsdt=struct.unpack_from('<Q',r,24)[0]
 root=save_table(xsdt or rsdt);step=8 if xsdt else 4;fmt='<Q' if xsdt else '<I'
 if not result['tables'][-1]['checksum_valid']:raise ValueError('root table checksum invalid')
 for pos in range(36,len(root),step):
  pa=struct.unpack_from(fmt,root,pos)[0]
  try:
   b=save_table(pa)
   if b[:4]==b'FACP':
    dsdt=struct.unpack_from('<I',b,40)[0]
    if len(b)>=148 and struct.unpack_from('<Q',b,140)[0]:dsdt=struct.unpack_from('<Q',b,140)[0]
    if dsdt:save_table(dsdt)
  except Exception as e:result['errors'].append(hex(pa)+': '+repr(e))
except Exception as e:result['errors'].append(repr(e))
(out/'summary.json').write_text(json.dumps(result,indent=2));print(result['errors'],flush=True)

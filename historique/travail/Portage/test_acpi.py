#!/usr/bin/env python3
from pathlib import Path
import re,subprocess,struct,json
root=Path(__file__).parent;source=root/'loader/linux/ps4-kexec-common/acpi.c';proof=Path('/project/PS4/portage-linux/recherche/acpi');build=root/'build';b=bytearray(65536)
for p in proof.glob('*.bin'):
 m=re.match(r'\w+_([0-9a-f]+)\.bin$',p.name)
 if m:
  off=int(m[1],16)-0xe0000;v=p.read_bytes()
  if not 0<=off<=65536-len(v):raise ValueError(p)
  b[off:off+len(v)]=v
fixture=build/'acpi_fixture.bin';fixture.write_bytes(b)
pre=build/'acpi_prelude.h';pre.write_text('#include <stdint.h>\n#include <stddef.h>\n#include <sys/types.h>\n#undef offsetof\n')
subprocess.run(['cc','-O1','-g','-DTESTING','-include',str(pre),'-ffunction-sections','-fdata-sections','-fsanitize=address','-Wl,--gc-sections',str(source),'-o',str(build/'acpi_test')],check=True)
r=subprocess.run([str(build/'acpi_test'),str(fixture)],capture_output=True,text=True);(proof/'native_fix_test.log').write_text(r.stdout+r.stderr);r.check_returncode()
a=fixture.read_bytes();assert a[:8]==b'RSD PTR ' and sum(a[:20])%256==0 and sum(a[:36])%256==0
root_pa=struct.unpack_from('<Q',a,24)[0];off=root_pa-0xe0000;n=struct.unpack_from('<I',a,off+4)[0];assert sum(a[off:off+n])%256==0
rows=[]
for pos in range(off+36,off+n,8):
 pa=struct.unpack_from('<Q',a,pos)[0];o=pa-0xe0000;length=struct.unpack_from('<I',a,o+4)[0];assert 0<=o and o+length<=len(a);table=a[o:o+length];assert sum(table)%256==0
 rows.append({'signature':table[:4].decode(),'physical':hex(pa),'size':length,'checksum_valid':True})
assert any(t['signature']=='IVRS' for t in rows)
(proof/'native_fix_test.json').write_text(json.dumps({'status':'PASS','address_sanitizer':'no memory error','rewritten_tables':rows},indent=2));print('PASS: actual console ACPI tables replayed through fix_acpi_tables with AddressSanitizer; rewritten roots and all tables including IVRS have valid checksums')

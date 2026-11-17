#!/usr/bin/env python3
from pathlib import Path
import struct,json
from ps4_transport import Debug
c=Debug();base=c.base();raw=c.kernel(base+0x2814270,16);flag,unused,pos=struct.unpack('<QII',raw)
if pos>0x20000:raise ValueError(f'Unexpected ring position {pos:#x}')
size=16384;start=(pos-size)%0x20000;data=b''
while len(data)<size:
 at=(start+len(data))%0x20000;n=min(4096,size-len(data),0x20000-at);data+=c.kernel(base+0x27e0230+at,n)
out=Path('/project/PS4/portage-linux/recherche');(out/'kernel_recent.log').write_bytes(data);(out/'kernel_log_state.json').write_text(json.dumps({'base':hex(base),'position':pos,'state_hex':raw.hex(),'source':'sysctl msgbuf handler 0x770470 -> log buffer RVA 0x27e0230'},indent=2));print(data.decode('utf-8','replace').replace('\x00',''))

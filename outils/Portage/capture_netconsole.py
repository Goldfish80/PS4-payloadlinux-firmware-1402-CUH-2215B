#!/usr/bin/env python3
"""Capture UDP kernel logs from this PS4, without a shell or login service."""
import argparse,socket,time,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=6666);p.add_argument('--seconds',type=int,default=600);p.add_argument('--source',default='192.0.2.10');p.add_argument('--output',type=Path,default=Path('/project/PS4/portage-linux/recherche/linux_netconsole.log'));a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',a.port));s.settimeout(1);deadline=time.monotonic()+a.seconds;count=0
print(f'Listening UDP {a.port} for {a.source}',flush=True)
with a.output.open('ab',buffering=0) as f:
 while time.monotonic()<deadline:
  try:data,peer=s.recvfrom(65535)
  except socket.timeout:continue
  if peer[0]!=a.source:continue
  count+=1;f.write(data)
  if not data.endswith(b'\n'):f.write(b'\n')
  if count==1 or count%50==0:print('packets',count,'last',data[:180].decode('utf-8','replace'),flush=True)
s.close();a.output.with_suffix('.status.json').write_text(json.dumps({'packets':count,'source':a.source,'port':a.port},indent=2));print('Capture complete',count,flush=True)

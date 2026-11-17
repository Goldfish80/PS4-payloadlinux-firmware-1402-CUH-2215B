#!/usr/bin/env python3
"""Capture the owner's existing TCP log stream, reconnecting after a reboot."""
import argparse,socket,time,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--ip',default='192.0.2.10');p.add_argument('--port',type=int,default=3232);p.add_argument('--seconds',type=int,default=3600);p.add_argument('--output',type=Path,default=Path('/project/PS4/portage-linux/recherche/orbis_live.log'));a=p.parse_args()
a.output.parent.mkdir(parents=True,exist_ok=True);deadline=time.monotonic()+a.seconds;total=0;connections=0
with a.output.open('ab',buffering=0) as f:
 while time.monotonic()<deadline:
  try:
   with socket.create_connection((a.ip,a.port),timeout=3) as s:
    s.settimeout(1);connections+=1;print('Connected',a.ip,a.port,'connection',connections,flush=True)
    while time.monotonic()<deadline:
     try:b=s.recv(65536)
     except socket.timeout:continue
     if not b:break
     f.write(b);total+=len(b)
  except OSError as e:print('Disconnected:',type(e).__name__,flush=True)
  time.sleep(2)
a.output.with_suffix('.status.json').write_text(json.dumps({'bytes':total,'connections':connections,'ip':a.ip,'port':a.port},indent=2))

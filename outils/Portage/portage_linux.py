#!/usr/bin/env python3
"""Préparer et lancer le chargeur vérifié de cette PS4 14.02 / Belize2 A0.
Les opérations de lancement ne sont jamais réessayées automatiquement.
"""
import argparse,hashlib,io,json,os,re,socket,struct,subprocess,time,zlib
from contextlib import closing
from datetime import datetime,timezone
from ftplib import FTP,error_perm
from pathlib import Path
from ps4_transport import Debug
ROOT=Path(__file__).resolve().parent;PROJECT=ROOT.parent
REPORTS=Path(os.environ.get('PS4_REPORTS',str(PROJECT.parent/'portage-linux')))
REMOTE='/data/linux/portage-linux';BOOT='/data/linux/boot'

def say(s):print(s,flush=True)
def utc():return datetime.now(timezone.utc).isoformat()
def ftp(ip,port):
 f=FTP();f.connect(ip,port,timeout=12);f.login();return f

def retrieve(ip,port,path,limit=512000):
 b=io.BytesIO()
 def put(data):
  if b.tell()+len(data)>limit:raise ValueError('Remote file exceeds size limit')
  b.write(data)
 with closing(ftp(ip,port)) as f:f.retrbinary('RETR '+path,put)
 return b.getvalue()
def store(ip,port,path,data):
 with closing(ftp(ip,port)) as f:
  temp=path+'.uploading'
  f.storbinary('STOR '+temp,io.BytesIO(data),blocksize=32768)
  f.voidcmd('TYPE I')
  if f.size(temp)!=len(data):raise RuntimeError('Incomplete FTP upload')
  f.rename(temp,path)
def preserve_log(ip,port,name):
 with closing(ftp(ip,port)) as f:
  try:f.rename(REMOTE+'/'+name,REMOTE+'/'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_')+name)
  except error_perm as e:
   if not str(e).startswith('550'):raise

def compatibility(c):
 base=c.base();fw=c.firmware()
 if fw!=1402:raise RuntimeError(f'Firmware mismatch: {fw}')
 if base&0x3fff or base>>48!=0xffff:raise RuntimeError('Invalid kernel base')
 if c.kernel(base,4)!=b'\x7fELF':raise RuntimeError('Missing kernel ELF header')
 manifest=json.loads((ROOT/'guard_manifest.json').read_text())
 for g in manifest:
  a=base+int(g['rva'],16)
  if c.kernel(a,16).hex()!=g['bytes']:raise RuntimeError('Signature mismatch: '+g['name'])
 subid=struct.unpack('<I',c.kernel(base+0x21d279c,4))[0]
 if subid!=0x40100:raise RuntimeError(f'Southbridge mismatch: {subid:#x}')
 l4,l3=struct.unpack('<II',c.kernel(base+0x1b2c394,8))
 if not 0<l4<512 or not 0<=l3<512:raise RuntimeError('Invalid direct-map indices')
 pstate=c.kernel(base+0x3a31af,5)
 if pstate not in (b'\xbf\x01\0\0\0',b'\xbf\x03\0\0\0'):raise RuntimeError('Unexpected pstate instruction')
 for off in (0x4669ec,0x4669f4):
  if c.kernel(base+off,1) not in (b'\x03',b'\x07'):raise RuntimeError('Unexpected allocation protection byte')
 call=struct.unpack('<Q',c.kernel(base+0x1102b70+153*48+8,8))[0]
 if call!=base+0x1c07a0:raise RuntimeError('Syscall 153 already occupied; refusing to overwrite it')
 edid=c.kernel(base+0x275e148,128)
 if edid[:8]!=b'\x00\xff\xff\xff\xff\xff\xff\x00' or sum(edid)%256:raise RuntimeError('Invalid or unavailable base EDID')
 dmap=0xffff800000000000|(l4<<39)|(l3<<30);rsdp=c.kernel(dmap+0xe0000,36)
 if rsdp[:8]!=b'RSD PTR ' or sum(rsdp[:20])%256 or sum(rsdp)%256:raise RuntimeError('Invalid ACPI RSDP')
 say(f'Compatibilité confirmée : FW {fw}, Belize2 A0, {len(manifest)} gardes, EDID et RSDP valides.')
 return {'firmware':fw,'kernel_base':hex(base),'southbridge':'Belize2 A0','subid':hex(subid),'guards':len(manifest),'dmap_base':hex(dmap),'syscall_153':'nosys','timestamp':utc()}

def select_target(c):
 target=next((p for p in c.processes() if p['name']=='fs_cleaner.elf'),None)
 if target is None:raise RuntimeError('Expected fs_cleaner.elf process unavailable')
 maps=c.maps(target['pid']);lib=next((m for m in maps if m['name']=='libkernel_sys.sprx' and m['prot']==5),None)
 if lib is None:raise RuntimeError('Expected libkernel_sys mapping unavailable')
 for off in (0x14010,0x14030,0x14450):
  a=lib['start']+off
  if not any(m['start']<=a and a+16<=m['end'] for m in maps):raise RuntimeError('Pthread entry not mapped')
  if c.process_read(target['pid'],a,4)!=b'\x55\x48\x89\xe5':raise RuntimeError('Pthread entry signature mismatch')
 a=lib['start']+0x8e830
 if not any(m['start']<=a and a+8<=m['end'] for m in maps):raise RuntimeError('Thread initialization pointer not mapped')
 target['libkernel_base']=hex(lib['start']);return target

def validate_preflight(data,bootargs):
 t=data.decode('utf-8','replace')
 if not t.endswith('PREFLIGHT_OK\n'):raise RuntimeError('Diagnostic incomplete or failed:\n'+t)
 for label,expected in [('SELF_FIRMWARE',1402),('USER_SUBID',0x40100),('GUARD_RESULT',0),('KEXEC_SYSCALL_RETURN',0)]:
  m=re.search(r'^'+label+r' (0x[0-9a-f]+)$',t,re.M)
  if not m or int(m[1],16)!=expected:raise RuntimeError('Unexpected diagnostic '+label)
 for name in ['bzImage','initramfs.cpio.gz','bootargs.txt']:
  b=bootargs if name=='bootargs.txt' else (PROJECT/'Multiboot'/name).read_bytes()
  pattern=r'FILE '+re.escape(BOOT+'/'+name)+r'\nSIZE (0x[0-9a-f]+) CRC32 (0x[0-9a-f]+)'
  m=re.search(pattern,t)
  if not m or int(m[1],16)!=len(b) or int(m[2],16)!=zlib.crc32(b):raise RuntimeError('Boot file size/CRC mismatch: '+name)
 return t

def probe(c,ip,port):
 preserve_log(ip,port,'preflight.log');target=select_target(c)
 say('Exécution du diagnostic sans patch du noyau et sans redémarrage...')
 c.elf(target['pid'],(ROOT/'build/preflight.elf').read_bytes())
 bootargs=retrieve(ip,port,BOOT+'/bootargs.txt',8192)
 last='No log yet';deadline=time.monotonic()+90
 while time.monotonic()<deadline:
  try:
   data=retrieve(ip,port,REMOTE+'/preflight.log',8192)
   (REPORTS/'recherche/preflight_runtime.log').write_bytes(data)
   if b'PREFLIGHT_FAILED' in data:raise RuntimeError(data.decode('utf-8','replace'))
   if data.endswith(b'PREFLIGHT_OK\n'):
    validate_preflight(data,bootargs);say('PREFLIGHT_OK : contrôles kernel et CRC complets des trois fichiers conformes.');return {'target':target,'log':data.decode(),'timestamp':utc()}
   last=data.decode('utf-8','replace')
  except (error_perm,socket.timeout,TimeoutError,ConnectionError) as e:last=repr(e)
  time.sleep(1)
 raise RuntimeError('No completed diagnostic within 90 seconds: '+last)

def build():
 env=os.environ.copy();env['PATH']=str(PROJECT/'Scout/toolchain/usr/bin')+os.pathsep+env.get('PATH','')
 subprocess.run(['make','-C',str(ROOT/'loader/linux/ps4-kexec-common'),'FW_DEFINE=PS4_14_02','BUILD_DIR='+str(ROOT/'loader/linux/kexec-build/1402')],env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 subprocess.run(['make','-C',str(ROOT/'loader/linux'),'payloads/linux-2048mb.bin'],env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
 flags=['-isystem',str(ROOT/'loader/freebsd-headers'),'-nostdinc','-nostdlib','-fno-stack-protector','-fno-asynchronous-unwind-tables','-static','-fPIE','-ffreestanding','-mno-red-zone','-mno-sse','-mno-sse2','-mno-mmx']
 subprocess.run(['cc',*flags,str(ROOT/'loader/lib/lib.a'),str(ROOT/'preflight.c'),str(ROOT/'loader/linux/fw_detect.c'),'-Wl,--gc-sections,--build-id=none,-Ttext-segment=0','-o',str(ROOT/'build/preflight.elf')],check=True)
 out={}
 for p in [ROOT/'build/preflight.elf',ROOT/'loader/linux/payloads/linux-2048mb.elf',ROOT/'loader/linux/payloads/linux-2048mb.bin']:
  out[p.name]={'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
 (ROOT/'build/artifacts.json').write_text(json.dumps(out,indent=2));say('Compilation terminée et empreintes enregistrées.');return out

def deploy(ip,port):
 files={
  '/data/payloads/linux-1402-belize2-checked.elf':ROOT/'loader/linux/payloads/linux-2048mb.elf',
  '/data/payloads/linux-1402-belize2-checked.bin':ROOT/'loader/linux/payloads/linux-2048mb.bin',
  REMOTE+'/preflight.elf':ROOT/'build/preflight.elf',
  REMOTE+'/portage_linux.py':ROOT/'portage_linux.py',
  REMOTE+'/ps4_transport.py':ROOT/'ps4_transport.py',
  REMOTE+'/guard_manifest.json':ROOT/'guard_manifest.json',
  REMOTE+'/artifacts.json':ROOT/'build/artifacts.json',
 }
 for name in ['RAPPORT_COMPLET.md','DOSSIER_1402_COMPLET.json','offsets_linux_1402.tsv']:
  if (REPORTS/name).exists():files[REMOTE+'/'+name]=REPORTS/name
 for remote,p in files.items():
  b=p.read_bytes();store(ip,port,remote,b);say('Déposé : '+remote)
 # Small control file checked by reading it back, large payload checked by FTP SIZE.
 remote=REMOTE+'/artifacts.json'
 if retrieve(ip,port,remote,16384)!=(ROOT/'build/artifacts.json').read_bytes():raise RuntimeError('FTP readback mismatch')
 return {'files':list(files),'artifacts':json.loads((ROOT/'build/artifacts.json').read_text()),'timestamp':utc()}

def diagnostic_bootargs(ip,port,netconsole=None):
 b=retrieve(ip,port,BOOT+'/bootargs.txt',8192);stamp=datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
 backup=REPORTS/'recherche'/('bootargs_'+stamp+'.original.txt');backup.write_bytes(b)
 store(ip,port,REMOTE+'/'+backup.name,b)
 args=b.decode('utf-8').split()
 args=[x for x in args if x!='quiet' and not x.startswith('loglevel=')]
 for word in ['loglevel=7','ignore_loglevel','ps4_rescue']:
  if word not in args:args.append(word)
 if netconsole:
  if not re.fullmatch(r'[0-9A-Za-z@:/.,_-]+',netconsole):raise ValueError('Invalid netconsole argument')
  args=[x for x in args if not x.startswith('netconsole=')]
  args.append('netconsole='+netconsole)
 data=(' '.join(args)+'\n').encode()
 if len(data)>2047:raise RuntimeError('Kernel command line too long')
 store(ip,port,BOOT+'/bootargs.txt',data)
 if retrieve(ip,port,BOOT+'/bootargs.txt',8192)!=data:raise RuntimeError('Bootargs readback mismatch')
 return {'local_backup':str(backup),'remote_backup':REMOTE+'/'+backup.name,'bootargs':data.decode()}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['check','build','deploy','boot','restore-bootargs']);p.add_argument('--ip',default=os.environ.get('PS4_IP','192.0.2.10'));p.add_argument('--debug-port',type=int,default=744);p.add_argument('--ftp-port',type=int,default=2121);p.add_argument('--diagnostic',action='store_true',help='Save original bootargs and request a verbose rescue shell');p.add_argument('--netconsole',help='Optional Linux UDP kernel-log target in documented netconsole syntax');a=p.parse_args()
 REPORTS.mkdir(exist_ok=True,parents=True);(REPORTS/'recherche').mkdir(exist_ok=True)
 state={'action':a.action,'started':utc(),'ip':a.ip};path=REPORTS/'recherche'/('operation_'+datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')+'.json')
 def save():path.write_text(json.dumps(state,indent=2))
 save()
 try:
  if a.action=='build':state['build']=build()
  elif a.action=='restore-bootargs':
   backups=sorted((REPORTS/'recherche').glob('bootargs_*.original.txt'))
   if not backups:raise RuntimeError('No saved bootargs')
   store(a.ip,a.ftp_port,BOOT+'/bootargs.txt',backups[-1].read_bytes());state['restored']=str(backups[-1])
  else:
   c=Debug(a.ip,a.debug_port,timeout=30);state['compatibility']=compatibility(c);save()
   if a.action in ('deploy','boot'):state['build']=build();state['deployment']=deploy(a.ip,a.ftp_port);save()
   if a.action=='boot' and a.diagnostic:state['bootargs']=diagnostic_bootargs(a.ip,a.ftp_port,a.netconsole);save()
   state['preflight']=probe(c,a.ip,a.ftp_port);save()
   if a.action=='boot':
    state['final_compatibility']=compatibility(c);target=select_target(c);state['launch_target']=target;state['launch']='about_to_send';save()
    preserve_log(a.ip,a.ftp_port,'loader.log');say('Envoi du chargeur ; arrêt normal puis tentative de démarrage Linux après armement réussi.')
    c.elf(target['pid'],(ROOT/'loader/linux/payloads/linux-2048mb.elf').read_bytes());state['launch']='transport_accepted';save()
    deadline=time.monotonic()+75
    while time.monotonic()<deadline:
     try:
      data=retrieve(a.ip,a.ftp_port,REMOTE+'/loader.log',32768);(REPORTS/'recherche/loader_runtime.log').write_bytes(data);state['loader_log']=data.decode('utf-8','replace');save()
      if b'KEXEC_ARMED' in data:state['launch']='kexec_armed';say(state['loader_log']);break
      if b'failed' in data.lower() or b'abort' in data.lower() or b'requires' in data.lower():raise RuntimeError(state['loader_log'])
     except (OSError,error_perm,EOFError) as e:state['log_transport_error']=repr(e)
     time.sleep(1)
    if state['launch']!='kexec_armed':raise RuntimeError('Kernel handoff not confirmed; inspect operation log and console display')
    state['boot_confirmation']='Kexec armed; Linux execution and HDMI output still require independent observation'
  state['status']='done';state['finished']=utc();save();say('État enregistré : '+str(path))
 except BaseException as e:
  state['status']='error';state['error']=repr(e);state['finished']=utc();save();raise
if __name__=='__main__':main()

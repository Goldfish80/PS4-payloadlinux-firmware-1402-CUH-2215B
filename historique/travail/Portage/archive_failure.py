#!/usr/bin/env python3
"""Archive evidence of the first real SG handoff without overwriting it."""
from pathlib import Path
from ftplib import FTP,error_perm
import hashlib,json,shutil,io,zipfile
ROOT=Path('/project/PS4/portage-linux');OUT=ROOT/'erreurs/2026-11-16_142419_extinction';OUT.mkdir(parents=True,exist_ok=True)
for name in ['ESSAI_MATERIEL_SG.md','ECOUTE_DISTANTE.md','operation_20261116_142419.json','loader_runtime.log','preflight_runtime.log','orbis_tcp3232.log','linux_netconsole.log','TESTS_SIMULTANES.md','virtual-pair-probe.log']:
 p=ROOT/'recherche'/name
 if p.exists():shutil.copy2(p,OUT/name)
if (ROOT/'recherche/apres_extinction').exists():shutil.copytree(ROOT/'recherche/apres_extinction',OUT/'apres_extinction',dirs_exist_ok=True)
for p in [Path('/tmp/ps4_sg_hardware_boot.log'),Path('/tmp/ps4_netconsole_boot.log')]:
 if p.exists():shutil.copy2(p,OUT/p.name)
f=FTP();f.connect('192.0.2.10',2121,timeout=15);f.login()
for remote,name in [('/data/payloads/linux-1402-belize2-checked.elf','payload_utilise.elf'),('/data/payloads/linux-1402-belize2-checked.bin','payload_utilise.bin'),('/data/linux/portage-linux/artifacts.json','empreintes_deployees.json')]:
 p=OUT/name
 if not p.exists():
  with p.open('wb') as dst:f.retrbinary('RETR '+remote,dst.write)
expected=json.loads((OUT/'empreintes_deployees.json').read_text())
for local,key in [('payload_utilise.elf','linux-2048mb.elf'),('payload_utilise.bin','linux-2048mb.bin')]:
 assert hashlib.sha256((OUT/local).read_bytes()).hexdigest()==expected[key]['sha256'],'Payload differs from deployed manifest'
(OUT/'LIRE_MOI.md').write_text('''# Échec de démarrage Linux : extinction de la PS4

Essai du 16 novembre 2026, lancé à 14:24:19 UTC.

- Préparation : firmware/signatures/CRC conformes ; KERNEL_STAGE_RESULT=0 ; KEXEC_LOAD_RESULT=0 ; KEXEC_ARMED.
- J’ai observé : la PS4 s’est éteinte, sans affichage Linux.
- Réseau : services Orbis disparus après arrêt, aucun paquet Linux netconsole reçu.
- Conclusion : démarrage Linux non réussi ; point exact de défaillance inconnu. L’armement ne démontre pas l’exécution du hook ni celle de Linux.
- Les payloads de ce dossier sont ceux relus sur la console après cet essai et comparés au manifeste déployé. La version source compilée ensuite contient des diagnostics supplémentaires : ne pas confondre les deux.
- orbis_tcp3232.log commence APRÈS le redémarrage suivant : il ne capture pas rétroactivement la première extinction. sce_log.bin est une copie brute du journal disque récupéré après coup ; son contenu doit être analysé avant attribution à cet incident.
- Aucun coredump trouvé dans /data/sce_coredumps ; cela ne suffit pas à exclure un crash noyau.

Voir ESSAI_MATERIEL_SG.md et operation_20261116_142419.json pour les détails.
''')
manifest={str(p.relative_to(OUT)):{'size':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in OUT.rglob('*') if p.is_file() and p.name!='INVENTAIRE.json'}
(OUT/'INVENTAIRE.json').write_text(json.dumps(manifest,indent=2))
archive=OUT.with_suffix('.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
 for p in OUT.rglob('*'):
  if p.is_file():z.write(p,p.relative_to(OUT))
remote='/data/linux/portage-linux/erreurs'
for d in [remote,remote+'/'+OUT.name]:
 try:f.mkd(d)
 except error_perm as e:
  if not str(e).startswith('550'):raise
for p in [OUT/'LIRE_MOI.md',OUT/'INVENTAIRE.json',OUT/'ESSAI_MATERIEL_SG.md',OUT/'loader_runtime.log',OUT/'operation_20261116_142419.json']:
 f.storbinary('STOR '+remote+'/'+OUT.name+'/'+p.name,io.BytesIO(p.read_bytes()))
with archive.open('rb') as src:f.storbinary('STOR '+remote+'/'+archive.name,src,32768)
f.voidcmd('TYPE I');assert f.size(remote+'/'+archive.name)==archive.stat().st_size
f.quit();print('Archivé localement et sur PS4 :',OUT,'archive',archive.stat().st_size,flush=True)

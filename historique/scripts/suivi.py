#!/usr/bin/env python3
"""Copie consultable du travail et publication du suivi sur la PS4."""
import argparse,hashlib,json,shutil,time,zipfile,os
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent;PROJECT=ROOT.parent
OUT=PROJECT.parent/'portage-linux';MIRROR=OUT/'travail';REMOTE='/data/linux/portage-linux'
def utc():return datetime.now(timezone.utc).isoformat()
def event(message,**fields):
 with (OUT/'JOURNAL_AVANCEMENT.jsonl').open('a') as f:f.write(json.dumps({'recorded_utc':utc(),'message':message,**fields},ensure_ascii=False)+'\n')
def files():
 for directory,label in [(ROOT,'Portage'),(PROJECT/'Scout/host','Scout/host')]:
  for p in directory.rglob('*'):
   if p.is_file() and '.git' not in p.parts and '__pycache__' not in p.parts and p.name!='.git':yield p,Path(label)/p.relative_to(directory)
def refresh(previous=None):
 previous=previous or {};current={};changed=[]
 for p,rel in files():
  st=p.stat();key=str(rel);sig=[st.st_mtime_ns,st.st_size];current[key]=sig
  if previous.get(key)!=sig or not (MIRROR/rel).exists():
   target=MIRROR/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target);changed.append(key)
 for p in Path('/tmp').glob('ps4*log'):
  if p.is_file() and p.stat().st_size<2000000:
   target=OUT/'recherche/commandes'/p.name;target.parent.mkdir(parents=True,exist_ok=True)
   if not target.exists() or target.stat().st_mtime_ns!=p.stat().st_mtime_ns:shutil.copy2(p,target)
 for name in ['probe_virtual_allocator.py','probe_virtual_pair.py','test_reloc_stage.py','probe_allocator.py','read_kernel_log.py','capture_netconsole.py','portage_linux.py','ps4_transport.py','suivi.py']:
  if (ROOT/name).exists():shutil.copy2(ROOT/name,OUT/'scripts'/name)
 if changed:event('Instantané des sources et artefacts mis à jour',files_changed=len(changed),paths=changed if previous else ['inventaire initial complet'])
 (OUT/'INVENTAIRE_TRAVAIL.json').write_text(json.dumps({'updated_utc':utc(),'source_root':str(ROOT),'mirror_root':str(MIRROR),'files':current},indent=2))
 write_summary()
 return current,changed

def write_summary():
 phase='Linux exécuté : messages CRNG/HWRNG observés à l’écran ; shell et système à confirmer.'
 doc=f'''# Suivi du portage PS4 — état visible

Dernière actualisation UTC : {utc()}

**{phase}**

## Où consulter le travail

- Sources actives et exécutables sur ce PC : `/project/PS4/Linux/Portage/`.
- Copie de tous les fichiers de travail, y compris compilations et tests : [travail/Portage](travail/Portage/).
- Scripts de collecte précédents : [travail/Scout/host](travail/Scout/host/).
- Rapports et résultats bruts : [recherche](recherche/).
- Inventaire des fichiers copiés : [INVENTAIRE_TRAVAIL.json](INVENTAIRE_TRAVAIL.json).
- Journal des actualisations : [JOURNAL_AVANCEMENT.jsonl](JOURNAL_AVANCEMENT.jsonl).
- Archive du travail courant : `suivi-travail.zip`.

Les copies isolées dans `scripts/` sont destinées à la consultation. Exécuter les scripts depuis leur dossier source actif, où les dépendances et les chemins sont corrects.

## Avancées et limites établies

2. Table 14.02 retrouvée dans la source conservée, commit 741b0ef96780afbb262ea7ea3958bcb3dcd09067. 33 entrées, 25 fenêtres de 96 octets live identiques au dump. Les noms restent attribués aux sources ; cela ne constitue pas une preuve sémantique de chaque fonction.
3. Belize2 A0 confirmé (`0x40100`), CPUID `0x710fc0`, brand `DG1701SNF87IG`. ACPI récupérée, checksums contrôlés et réécriture testée sous AddressSanitizer. Huit en-têtes de microcodes GPU de tailles conformes.
4. Diagnostic réel `PREFLIGHT_OK` : firmware, southbridge, gardes et CRC des fichiers entiers sur la console. Code et résultats disponibles ci-dessous.
5. Chargeur corrigé et compilé, puis réellement essayé. Il a installé kexec, mais `kexec_load` a renvoyé **12 / ENOMEM**. Le chargeur n’a pas demandé de redémarrage. [Journal réel du chargeur](recherche/loader_runtime.log).
6. Le syscall 153 installé par notre essai a été remis à nosys après contrôle d’appartenance du handler ; son blob a été libéré. Pas de réinjection aveugle d’un syscall occupé.
7. Comparaison d’allocations effectuée avec **les deux flags 0x101 et 0x102**. Les tailles 16 Ko, 64 Ko, 1 Mo réussissent. La taille réelle du noyau 20 718 592 octets et celle de l’initramfs avec réserve firmware échouent : `FW_CPIO_SIZE=131184`, total `12726774` octets, arrondi `12730368`. Cela établit un échec des grosses allocations contiguës avec ces paramètres, pas un manque démontré de RAM totale. [Matrice complète](recherche/allocator_probe_matrix.log).
8. Un autre test réel avec `kmem_alloc`, qui réserve une plage virtuelle continue, réussit pour environ 20 Mo et 12 Mo. Les adresses physiques du début et de la fin sont différentes et non contiguës ; certaines pages sont au-dessus de 4 Gio. [Résultat brut](recherche/virtual_allocator.log).
9. Cette alternative ne peut pas être branchée seule : l’ancien thunk suppose une plage physique unique pour le noyau et l’initramfs. Une adaptation de la relocalisation par pages est en préparation. Le planificateur de copies a passé **20 000 tests aléatoires**, chevauchements, cycles et bornes mémoire compris. **Intégré dans les sources et compilé ; aucun démarrage PS4 réussi de ce nouveau chemin n’est encore établi.**
10. Test simultané réel : 2042 pages distinctes, dont 224 au-delà de 4 Gio ; 33 456 128 octets écrits puis vérifiés sans erreur ; deux allocations libérées. Le test révèle 224 erreurs de conversion par OU binaire et aucune par addition. Macros de direct map corrigées par addition/soustraction dans les sources. [Journal](recherche/virtual-pair-probe.log).

## Fichiers demandés explicitement

- [probe_virtual_allocator.py](scripts/probe_virtual_allocator.py)
- [Sortie « Virtual-allocation probe sent »](recherche/probe_virtual_allocator.stdout.log)
- [Journal du test virtuel](recherche/virtual_allocator.log)
- [probe_allocator.py](scripts/probe_allocator.py)
- [Allocations flags 0x101 / 0x102](recherche/allocator_probe_matrix.log)
- [Code C de planification des copies](travail/Portage/loader/linux/ps4-kexec-common/reloc_plan.c)
- [Tests du planificateur](travail/Portage/test_reloc_plan.c)
- [Résultat des 20 000 tests](recherche/reloc_plan_test.stdout.log)
- [État de reprise détaillé](travail/Portage/ETAT_TRAVAIL.md)

## Prochaine étape

Confirmer également l’allocation virtuelle à la taille exacte de l’initramfs augmenté des firmwares, puis intégrer la copie finale par pages avec contrôle des recouvrements, de la limite physique et du protocole de boot Linux. Tester l’ensemble avant le prochain essai matériel. Linux n’est pas présenté comme démarré tant qu’aucune observation Linux indépendante ne le confirme.

Sur la console : dossier `/data/linux/portage-linux/`, fichier `SUIVI.md`, archive `suivi-travail.zip` et résultats de diagnostic. Le miroir local est actualisé pendant la poursuite du travail.
'''
 (OUT/'SUIVI.md').write_text(doc)

def archive():
 p=OUT/'suivi-travail.zip';temp=p.with_suffix('.zip.tmp')
 with zipfile.ZipFile(temp,'w',zipfile.ZIP_DEFLATED,compresslevel=4) as z:
  for directory in [MIRROR,OUT/'scripts',OUT/'recherche']:
   for f in directory.rglob('*'):
    if f.is_file():z.write(f,str(f.relative_to(OUT)))
  for name in ['SUIVI.md','JOURNAL_AVANCEMENT.jsonl','INVENTAIRE_TRAVAIL.json','RAPPORT_COMPLET.md','DOSSIER_1402_COMPLET.json']:
   if (OUT/name).exists():z.write(OUT/name,name)
 os.replace(temp,p);return p

def publish():
 from portage_linux import store
 p=archive()
 for name in ['SUIVI.md','JOURNAL_AVANCEMENT.jsonl','INVENTAIRE_TRAVAIL.json','suivi-travail.zip']:
  store('192.0.2.10',2121,REMOTE+'/'+name,(OUT/name).read_bytes())
 for name in ['probe_virtual_allocator.py','probe_allocator.py','portage_linux.py','ps4_transport.py']:
  store('192.0.2.10',2121,REMOTE+'/'+name,(ROOT/name).read_bytes())
 for name in ['virtual_allocator.log','allocator_probe_matrix.log','probe_virtual_allocator.stdout.log','reloc_plan_test.stdout.log','loader_runtime.log']:
  if (OUT/'recherche'/name).exists():store('192.0.2.10',2121,REMOTE+'/'+name,(OUT/'recherche'/name).read_bytes())
 event('Suivi publié sur la console',remote=REMOTE,archive_size=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
 print('Suivi publié :',REMOTE,'archive',p.stat().st_size,flush=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--publish',action='store_true');p.add_argument('--watch',action='store_true');a=p.parse_args();OUT.mkdir(exist_ok=True,parents=True);(OUT/'scripts').mkdir(exist_ok=True)
 prior={}
 try:prior=json.loads((OUT/'INVENTAIRE_TRAVAIL.json').read_text()).get('files',{})
 except (FileNotFoundError,ValueError):pass
 state,changed=refresh(prior)
 if changed or not (OUT/'suivi-travail.zip').exists():archive()
 if a.publish:publish()
 if a.watch:
  print('Miroir de travail actif :',MIRROR,flush=True)
  while True:
   time.sleep(5);state,changed=refresh(state)
   if changed:print('Actualisation :',len(changed),'fichiers',flush=True)
if __name__=='__main__':main()

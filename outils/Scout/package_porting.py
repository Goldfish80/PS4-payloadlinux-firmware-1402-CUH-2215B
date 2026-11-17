#!/usr/bin/env python3
from pathlib import Path
import json,csv,re,subprocess,hashlib,zipfile,shutil
ROOT=Path('/project/PS4/Linux');out=Path('/project/PS4/portage-linux');m=json.loads((out/'collection.json').read_text());src=ROOT/'Scout/upstream/linux-loader-reference';cat=ROOT/'Scout/reports/catalog_20261116_040009'
commit=subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()
magic=(src/'linux/magic.h').read_text().split('#elif defined PS4_14_00')[1].split('#endif')[0]
reference=[{'name':n,'rva_1400':v,'status':'REFERENCE 14.00 uniquement; NON VALIDE pour 14.02'} for n,v in re.findall(r'#define kern_off_(\w+)\s+(0x[\da-fA-F]+)',magic)]
verified={r['name']:r for r in m['offsets']}
for r in reference:
 key={'sysent':'sysents'}.get(r['name'],r['name'])
 if key in verified:r['rva_1402_source']=verified[key]['rva'];r['status']='source 14.02 et lecture live; voir collection.json pour niveau de preuve'
 else:r['rva_1402_source']='';r['status']='MANQUANT 14.02; reference 14.00 non transposable sans preuve'
fields=sorted(set().union(*(r.keys() for r in m['offsets'])))
with (out/'offsets_1402.tsv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=fields,delimiter='\t');w.writeheader();w.writerows(m['offsets'])
with (out/'besoins_kexec.tsv').open('w') as f:
 w=csv.DictWriter(f,fieldnames=['name','rva_1400','rva_1402_source','status'],delimiter='\t');w.writeheader();w.writerows(reference)
guards=sum(r.get('guard_matches_live',False) for r in m['offsets'])
text=f'''# Dossier de recherche : PS4 / portage Linux / firmware 14.02

Collecte UTC : {m['timestamp']}.
Ce dossier contient les observations obtenues et les lacunes identifiées. Il ne constitue pas un portage Linux terminé ni un chargeur 14.02 validé.

## Console et accès vérifiés

IP 192.0.2.10. ps4debug répond sur TCP 744 ; FTP GoldHEN v2.2 répond sur 2121, connexion anonyme. Les ports 21, 774, 9090 et 9020 ont refusé la connexion lors des essais.
Le firmware brut renvoyé est {m['firmware_raw']} (0x57a), interprété comme la clé 1402 par les sources ps4debug. Ce n'est pas un codage BCD.
Base noyau actuelle : {m['live_base']}. Les 4096 premiers octets sont identiques au dump local : {m.get('live_head_matches_dump')}.
Le modèle CUH-2215B et Belize2 A0 figurent dans les anciens scripts : ces indications n'ont pas été vérifiées indépendamment sur le matériel pendant cette collecte. Les chaînes Belize dans un noyau multi-matériel ne suffisent pas à identifier le southbridge.
L'ancien champ platform_id=4 est conservé comme donnée historique ; il ne faut pas l'assimiler sans preuve à SB_BELIZE2=4 du chargeur, qui est une autre énumération.

## Noyau et adresses

Dump local : Scout/reports/kernel_20261115_full.elf, 20080272 octets.
SHA256 : {m['dump_sha256']}.
Base historique : 0xffffffffc7114000 ; entrée RVA 0x6a410 ; base de lien supposée par les analyseurs : 0xffffffff82200000 ; slide historique 0x44f14000.
La concordance d'une page et de signatures ne prouve pas l'identité de l'intégralité des 20 Mo avec la mémoire actuelle.
Adresse actuelle = base actuelle + RVA. Un offset fichier n'est PAS toujours un RVA : utiliser les program headers ELF.
Les régions BSS absentes du fichier demandent une lecture live ; une valeur de pointeur live n'est pas un offset stable.
Les STRTAB et SYMTAB du dump sont intégralement nulles ; la table HASH existe, mais ne restitue pas les noms effacés. Le catalogue précédent contient 45038 relocations relatives, 18507 chaînes et 21926 cibles exécutables candidates, sans identité de fonction démontrée.

## Offsets extraits du SDK 14.02 et contrôlés

{len(m['offsets'])} entrées ; {guards} signatures de 8 octets correspondent en mémoire aux gardes du SDK. Les noms proviennent du code source ps4debug-NG, pas de symboles retrouvés dans le dump. Un prologue identique est une vérification de cohérence, pas une preuve sémantique indépendante.
Les autres entrées sont des variables globales du SDK dont les octets ont été lus ; leur rôle ne découle pas de leur seule valeur.

| Nom source | RVA | Octets live | Garde SDK live |
|---|---|---|---|
'''
for r in m['offsets']:text+=f"| {r['name']} | {r['rva']} | {r.get('live_bytes',r.get('error',''))} | {r.get('guard_matches_live','sans garde')} |\n"
text+='''
Les vm_map_lock/unlock ont des wrappers spécifiques dans le SDK : consulter leurs prototypes, fichiers et paramètres de ligne avant tout appel.
Le fichier extra_live.json contient notamment les indices pml4/dmap. Ils sont lus à des positions issues de la référence 14.00 et restent à valider comme structures.
Le désassemblage de kmem_alloc à RVA 0x466920 référence directement kernel_map à 0x22d1d50 ainsi que vm_map_lock 0x2f7d30, vm_map_findspace 0x2faf40 et vm_map_insert 0x2f9080 : cela ajoute une cohérence structurelle au-delà du simple prologue.

## Chargeur Linux et éléments manquants

'''
text+=f'Source téléchargée : https://github.com/SENeoV/ps4-linux-loader-ps4linux ; commit {commit}. Le dépôt parent https://github.com/ps4-linux/ps4-linux-loader a échoué avec Repository not found lors du clonage ; le fork est conservé comme référence datée.\n\n'
text+='''La référence s'arrête à 1400 dans fw_table, la normalisation du firmware et les images kexec intégrées. Ajouter seulement une ligne d'offsets au premier niveau ne suffit pas : il faut aussi une configuration kexec 1402 et les points d'accrochage/structures du noyau.
La liste détaillée des besoins est dans besoins_kexec.tsv. Les références 14.00 y sont explicitement marquées non validées pour 14.02.

| Besoin kexec | Référence 14.00 | Source 14.02 disponible |
|---|---|---|
'''
for r in reference:text+=f"| {r['name']} | {r['rva_1400']} | {r['rva_1402_source'] or 'A retrouver'} |\n"
text+='''
Points encore à établir : ICC/shutdown, fonctions de fréquences GPU et pstate, allocations contiguës/libération, pmap, rendez-vous SMP, copyin/copyout/copyinstr, détection GPU/southbridge, données EDID et matériel. Les positions et octets exacts des patches kmem_alloc demandent une analyse d'instructions, pas une addition de delta.
Les fonctions connues printf et kmem_alloc décalent de +0x360 et +0x3e0 depuis cette référence 14.00 ; kern_reboot de +0x370. Un delta unique est donc déjà réfuté par les entrées SDK elles-mêmes.
L'essai exploratoire copyin = 14.00 + 0x360 tombe au milieu d'instructions et n'est PAS un offset utilisable (disassembly_candidates.txt). Le candidat GPU +0x3c0 n'est pas identifié sémantiquement.
Les clés de disque ne sont pas nécessaires à un premier démarrage USB ; aucune clé personnelle n'a été extraite.

## Fichiers Linux présents et diagnostic de démarrage

Inventaire FTP : /data/linux/boot contient bzImage, initramfs.cpio.gz et bootargs.txt ; /data/payloads contient linux-2048mb.bin.
Les tailles interrogées sur la console sont dans boot_files.json. Une taille identique ne prouve pas une identité de contenu.
Les fichiers locaux Multiboot/kernel.info, kernel.config et bootargs.txt sont joints : ils décrivent un noyau Strawberry 7.3.3, branche ps4/7.3.3, commit 4025a70665daa096374a9fec8ade87435547d0e8, d'après les métadonnées locales ; cela ne confirme pas quel noyau a déjà démarré sur cette console.
Le bootargs récupéré utilise quiet loglevel=1 et panic=0 : les erreurs peuvent devenir invisibles et une panique rester figée. Pour un prochain essai instrumenté, préparer une copie avec quiet retiré, loglevel=7 et ignore_loglevel ; décider du watchdog/panic selon le moyen de capturer les logs. Aucun argument de boot existant n'a été modifié.
Les journaux récupérés concernent surtout d'autres applications ; ils ne constituent pas une trace de démarrage Linux.

## Suite technique reproductible

1. Importer le dump ELF dans Ghidra avec ses segments ; conserver la distinction RVA/offset fichier.
2. Nommer les fonctions du SDK comme annotations issues de source et exploiter leurs appels/références pour confirmer leur rôle.
3. Retrouver les fonctions kexec restantes au moyen de leurs chaînes, graphes d'appels et comparaisons avec un noyau 14.00 obtenu légitimement ; ne pas extrapoler les décalages.
4. Confirmer le southbridge et les paramètres GPU avec des lectures documentées des structures ou un inventaire PCI/ACPI. Le modèle présumé ne suffit pas.
5. Produire une configuration kexec 1402 avec contrôles d'octets exacts pour chaque patch, résoudre toutes les dépendances, puis compiler. Un boot Linux n'a pas été exécuté durant cette collecte.

## Preuves, erreurs et reproduction

collection.json et offsets_1402.tsv : mesures live et provenance. ftp_inventory.json : fichiers listés, sans contenu des fichiers personnels. extra_live.json : lectures complémentaires. boot_files.json : tailles/hashes et échecs de transferts. Les échecs sont conservés ; un fichier partiel ne doit pas être traité comme un téléchargement réussi.
Le premier ps4_scout_master a obtenu version, branding, firmware et base, puis a expiré sur une lecture. Des lectures sur connexions séparées ont ensuite réussi. Le collecteur fourni utilise cette stratégie ; la cause précise du timeout initial n'est pas démontrée.
Les connexions refusées et transferts expirés ne sont pas des offsets manquants que l'on pourrait inventer.
Reproduction de la collecte : python /project/PS4/Linux/Scout/host/collect_porting.py ; cette commande relit la console et remplace les fichiers de collecte du dossier local. Elle ne patche pas le noyau.
Le dossier contient aussi les catalogues historiques et les sources pertinentes pour reprendre le travail sans dépendre de liens mouvants.
'''
(out/'RAPPORT_COMPLET.md').write_text(text)
# Contenu intégral du catalogue dans un document machine autonome.
full={'collection':m,'reference_commit':commit,'besoins_kexec':reference,'catalog_summary':json.loads((cat/'summary.json').read_text()),'catalog_tsv':{p.name:p.read_text() for p in cat.glob('*.tsv')},'report_markdown':text}
for name in ['extra_live.json','boot_files.json','ftp_inventory.json']:
 if (out/name).exists():full[name]=json.loads((out/name).read_text())
(out/'DOSSIER_COMPLET.json').write_text(json.dumps(full,ensure_ascii=False,indent=2))
proof=out/'preuves';proof.mkdir(exist_ok=True)
for p in [ROOT/'Scout/reports/kernel_20261115_full.elf',ROOT/'Scout/reports/master_20261116_041457/report.json',ROOT/'Scout/reports/sce_audit_20261116_035920/summary.txt',ROOT/'Multiboot/kernel.info',ROOT/'Multiboot/kernel.config',ROOT/'Multiboot/bootargs.txt',ROOT/'Scout/host/collect_porting.py',ROOT/'Scout/host/package_porting.py',ROOT/'Scout/upstream/ps4debug-NG/ps4-ksdk/source/ksdk.c',src/'linux/fw_offsets.h',src/'linux/magic.h',src/'linux/fw_detect.c',src/'freebsd-headers/ps4-offsets/1400.h']:
 shutil.copy2(p,proof/p.name)
for p in cat.glob('*'):
 shutil.copy2(p,proof/('catalog_'+p.name))
manifest={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob('*') if p.is_file() and p.name not in ['SHA256SUMS.json','portage-linux-complet.zip','upload_status.json']}
(out/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2))
with zipfile.ZipFile(out/'portage-linux-complet.zip','w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
 for p in out.rglob('*'):
  if p.is_file() and p.name not in ['portage-linux-complet.zip','upload_status.json']:z.write(p,str(p.relative_to(out)))
print('rapport',len(text),'offsets',len(m['offsets']),'gardes',guards,'archive',(out/'portage-linux-complet.zip').stat().st_size)

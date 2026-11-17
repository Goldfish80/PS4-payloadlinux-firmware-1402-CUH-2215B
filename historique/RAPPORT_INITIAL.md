# Dossier de recherche : PS4 / portage Linux / firmware 14.02

Collecte UTC : 2026-11-16T04:16:21.466913+00:00.
Ce dossier contient les observations obtenues et les lacunes identifiées. Il ne constitue pas un portage Linux terminé ni un chargeur 14.02 validé.

## Console et accès vérifiés

IP 192.0.2.10. ps4debug répond sur TCP 744 ; FTP GoldHEN v2.2 répond sur 2121, connexion anonyme. Les ports 21, 774, 9090 et 9020 ont refusé la connexion lors des essais.
Le firmware brut renvoyé est 1402 (0x57a), interprété comme la clé 1402 par les sources ps4debug. Ce n'est pas un codage BCD.
Base noyau actuelle : 0xffffffffc7114000. Les 4096 premiers octets sont identiques au dump local : True.
Le modèle CUH-2215B et Belize2 A0 figurent dans les anciens scripts : ces indications n'ont pas été vérifiées indépendamment sur le matériel pendant cette collecte. Les chaînes Belize dans un noyau multi-matériel ne suffisent pas à identifier le southbridge.
L'ancien champ platform_id=4 est conservé comme donnée historique ; il ne faut pas l'assimiler sans preuve à SB_BELIZE2=4 du chargeur, qui est une autre énumération.

## Noyau et adresses

Dump local : Scout/reports/kernel_20261115_full.elf, 20080272 octets.
SHA256 : bfe5b4efae4f025674dc6346eb327bd4b69edb42dbb15895177a6ea51d2ded39.
Base historique : 0xffffffffc7114000 ; entrée RVA 0x6a410 ; base de lien supposée par les analyseurs : 0xffffffff82200000 ; slide historique 0x44f14000.
La concordance d'une page et de signatures ne prouve pas l'identité de l'intégralité des 20 Mo avec la mémoire actuelle.
Adresse actuelle = base actuelle + RVA. Un offset fichier n'est PAS toujours un RVA : utiliser les program headers ELF.
Les régions BSS absentes du fichier demandent une lecture live ; une valeur de pointeur live n'est pas un offset stable.
Les STRTAB et SYMTAB du dump sont intégralement nulles ; la table HASH existe, mais ne restitue pas les noms effacés. Le catalogue précédent contient 45038 relocations relatives, 18507 chaînes et 21926 cibles exécutables candidates, sans identité de fonction démontrée.

## Offsets extraits du SDK 14.02 et contrôlés

28 entrées ; 21 signatures de 8 octets correspondent en mémoire aux gardes du SDK. Les noms proviennent du code source ps4debug-NG, pas de symboles retrouvés dans le dump. Un prologue identique est une vérification de cohérence, pas une preuve sémantique indépendante.
Les autres entrées sont des variables globales du SDK dont les octets ont été lus ; leur rôle ne découle pas de leur seule valeur.

| Nom source | RVA | Octets live | Garde SDK live |
|---|---|---|---|
| Xfast_syscall | 0x1c0 | 0f01f86548892425 | True |
| printf | 0x2e0b20 | 554889e5534883ec | True |
| malloc | 0x9520 | 554889e541574156 | True |
| free | 0x96e0 | 554889e541574156 | True |
| memcpy | 0x2bdb50 | 554889e54989fa49 | True |
| memset | 0x1fa900 | 554889e553504889 | True |
| memcmp | 0x3950f0 | 554889e54885d274 | True |
| kmem_alloc | 0x466920 | 554889e541574156 | True |
| strlen | 0x36b910 | 554889e5488d47ff | True |
| create_thread | 0x4c6c0 | 554889e541574156 | True |
| kern_reboot | 0x3a2bc0 | 554889e541574156 | True |
| vm_map_lookup_entry | 0x2f84c0 | 554889e541574156 | True |
| vm_map_delete | 0x2fa980 | 554889e541574156 | True |
| vm_map_protect | 0x2fcce0 | 554889e541574156 | True |
| vm_map_findspace | 0x2faf40 | 554889e541574156 | True |
| vm_map_insert | 0x2f9080 | 554889e541574156 | True |
| proc_rwmem | 0x366d80 | 554889e541574156 | True |
| disable_console_output | 0x1a47f90 | 000a2a0828030000 | sans garde |
| M_TEMP | 0x1520d00 | c06fb5c8ffffffff | sans garde |
| kernel_map | 0x22d1d50 | 00000014bbabffff | sans garde |
| prison0 | 0x111fa18 | 1001b7c8ffffffff | sans garde |
| rootvnode | 0x2136e90 | e801ba16bbabffff | sans garde |
| allproc | 0x1b28538 | 684b0457bbabffff | sans garde |
| sysents | 0x1102b70 | 0000000000000000 | sans garde |
| vm_map_lock_read | 0x2f7e80 | 554889e580bf1a01 | True |
| vm_map_unlock_read | 0x2f7ed0 | 554889e541565380 | True |
| vm_map_lock | 0x2f7d30 | 554889e5535080bf | True |
| vm_map_unlock | 0x2f7da0 | 554889e541565380 | True |

Les vm_map_lock/unlock ont des wrappers spécifiques dans le SDK : consulter leurs prototypes, fichiers et paramètres de ligne avant tout appel.
Le fichier extra_live.json contient notamment les indices pml4/dmap. Ils sont lus à des positions issues de la référence 14.00 et restent à valider comme structures.
Le désassemblage de kmem_alloc à RVA 0x466920 référence directement kernel_map à 0x22d1d50 ainsi que vm_map_lock 0x2f7d30, vm_map_findspace 0x2faf40 et vm_map_insert 0x2f9080 : cela ajoute une cohérence structurelle au-delà du simple prologue.

## Chargeur Linux et éléments manquants

Source téléchargée : https://github.com/SENeoV/ps4-linux-loader-ps4linux ; commit 581438f804f5fc288cf310abad585f93260e4f1d. Le dépôt parent https://github.com/ps4-linux/ps4-linux-loader a échoué avec Repository not found lors du clonage ; le fork est conservé comme référence datée.

La référence s'arrête à 1400 dans fw_table, la normalisation du firmware et les images kexec intégrées. Ajouter seulement une ligne d'offsets au premier niveau ne suffit pas : il faut aussi une configuration kexec 1402 et les points d'accrochage/structures du noyau.
La liste détaillée des besoins est dans besoins_kexec.tsv. Les références 14.00 y sont explicitement marquées non validées pour 14.02.

| Besoin kexec | Référence 14.00 | Source 14.02 disponible |
|---|---|---|
| printf | 0x2E07C0 | 0x2e0b20 |
| snprintf | 0x2E0AC0 | A retrouver |
| copyin | 0x2BDA40 | A retrouver |
| copyout | 0x2BD950 | A retrouver |
| copyinstr | 0x2BDEF0 | A retrouver |
| kmem_alloc_contig | 0x24D780 | A retrouver |
| kmem_free | 0x466710 | A retrouver |
| pmap_extract | 0x573D0 | A retrouver |
| pmap_protect | 0x58570 | A retrouver |
| sched_pin | 0x2319B0 | A retrouver |
| sched_unpin | 0x2319D0 | A retrouver |
| smp_rendezvous | 0x1AD880 | A retrouver |
| smp_no_rendevous_barrier | 0x1AD690 | A retrouver |
| icc_query_nowait | 0x448630 | A retrouver |
| kernel_map | 0x22d1d50 | 0x22d1d50 |
| sysent | 0x1102b70 | 0x1102b70 |
| kernel_pmap_store | 0x1b2c3a0 | A retrouver |
| Starsha_UcodeInfo | 0x0 | A retrouver |
| gpu_devid_is_9924 | 0x4AD0A0 | A retrouver |
| gc_get_fw_info | 0x4BBA50 | A retrouver |
| pml4pml4i | 0x1b2c390 | A retrouver |
| dmpml4i | 0x1b2c394 | A retrouver |
| dmpdpi | 0x1b2c398 | A retrouver |
| eap_hdd_key | 0x26c4cf0 | A retrouver |
| edid | 0x275e148 | A retrouver |
| wlanbt | 0x479550 | A retrouver |
| kern_reboot | 0x3A2850 | 0x3a2bc0 |
| set_gpu_freq | 0x4BA590 | A retrouver |
| set_pstate | 0x4BC960 | A retrouver |
| update_vddnp | 0x4BAB30 | A retrouver |
| set_cu_power_gate | 0x4BAF40 | A retrouver |
| pstate_before_shutdown | 0x3A2E40 | A retrouver |
| set_nclk_mem_spd | 0x4373F0 | A retrouver |

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
Le dossier contient aussi les catalogues historiques et les sources pertinentes pour reprendre le travail sans dépendre de liens mouvants.

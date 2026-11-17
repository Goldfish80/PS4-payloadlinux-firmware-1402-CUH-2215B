# PS4 14.02 / Belize2 A0 — dossier complet actualisé

Mise à jour UTC : 2026-11-16T05:13:43.288683+00:00

**Chargeur construit ; diagnostic exécuté avec succès ; essai de démarrage Linux pas encore confirmé.**

Ce rapport remplace le premier rapport, qui s'appuyait sur un fork antérieur à 14.02. Les valeurs de la nouvelle table ne sont plus manquantes : elles ont été retrouvées dans une copie plus récente du chargeur, puis confrontées au dump et à la console. La correspondance d'octets ne prouve pas à elle seule le nom d'une fonction ; la provenance et les contrôles structurels sont explicités ci-dessous.

## Console observée

- IP 192.0.2.10 ; ps4debug-NG TCP 744 ; FTP GoldHEN v2.2 TCP 2121.
- Firmware brut ps4debug : 1402 (0x57a). Le diagnostic exécuté sur la console le retrouve aussi via l'en-tête SELF de libc.
- Noyau : base actuelle 0xffffffffc7114000, dump historique 0xffffffffc7114000, entrée RVA 0x6a410.
- Chaîne du noyau : `r230516/release_branches/release_14.020 Oct 23 2026 05:24:24` (RVA 0x1520080 dans le dump).
- Southbridge **Belize2 A0**, identifiant 0x40100 relevé en mémoire. Ce n'est plus une simple hypothèse déduite du modèle.
- Le modèle CUH-2215B figure dans l'ancien contexte local ; il n'a pas été lu indépendamment depuis une étiquette ou une interface matérielle identifiant ce modèle précis.
- Le champ protocole `platform_id=4` est la constante PS4 du serveur (server.c). Il est distinct de l'énumération southbridge du chargeur.
- CPUID lu par le diagnostic : signature 0x710fc0, brand string `DG1701SNF87IG`. Le MADT énumère 8 APIC locaux activés.
- Direct map : 0xffffabbb00000000 ; indices DMPML4I=343 et DMPDPI=236 ; APIC local physique 0xfee00000 ; ECAM PCIe 0xf8000000, segment 0, bus 0..63.

Identification du southbridge : la relocation du nom `sce_subsys_subid` pointe vers le sysctl_oid à RVA 0x1a480a0. Son handler est 0x1d7980, qui appelle 0x1d73a0. Cette fonction lit la variable RVA 0x21d279c et reconnaît explicitement 0x40100. La valeur live est `00 01 04 00`. La correspondance du nom Belize2 A0 se trouve également dans GetSouthbridgeName du chargeur.
La valeur à RVA 0x23889a0 correspond à la signature CPUID observée ; le nom exploratoire `gpu_identity` dans les premiers fichiers ne doit pas faire prendre cette valeur pour un identifiant PCI GPU.
La fonction attribuée à gpu_devid_is_9924 à RVA 0x4ad480 lit le flag à 0x23889ac ; ce flag vaut 0 sur cette console. Le chargeur sélectionne donc son chemin Liverpool / non-Pro.

## Source conservée et problème trouvé

Copie de source : https://github.com/jclass/ps4-linux-loader ; commit `741b0ef96780afbb262ea7ea3958bcb3dcd09067`.
Le dépôt parent https://github.com/ps4-linux/ps4-linux-loader renvoyait 404 aux accès directs ; son annonce indexée de 14.02 a servi de piste, pas de preuve d'exécution. Le fork jclass contient effectivement les fichiers 1402.h, la table PS4_14_02 et la ligne fw_table 1402.

**Défaut d'intégration vérifié dans cette copie :** main-aio.c n'embarquait pas le blob kexec_1402 et ne le sélectionnait pas dans get_kexec_blob, malgré sa table d'offsets et sa règle de compilation. Le build corrigé embarque et sélectionne le blob 1402. Il est volontairement spécialisé pour cette console et cette paire de fichiers Linux.

## Table des offsets du chargeur

33 entrées issues de la table PS4_14_02. 25 fenêtres de 96 octets sont identiques entre le dump et la lecture live, y compris une entrée de données sysent et la fenêtre du point de patch pstate. Les variables BSS n'ont pas de contenu comparable dans le fichier ; elles ont été lues séparément. Starsha_UcodeInfo est facultatif et vaut 0 dans la source : gc_get_fw_info fournit l'alternative disponible.
Aucune valeur de clé personnelle de disque n'a été exportée dans ce dossier. L'offset eap_hdd_key reste attribué à la source, sans validation externe de la clé ; le chargeur conserve son mécanisme standard de transmission de cette clé en RAM à l'initramfs pour l'accès au disque PS4.

| Nom attribué par la source | RVA | Vérification |
|---|---|---|
| printf | 0x2e0b20 | 96 octets live = dump |
| snprintf | 0x2e0e20 | 96 octets live = dump |
| copyin | 0x2bdd40 | 96 octets live = dump |
| copyout | 0x2bdc50 | 96 octets live = dump |
| copyinstr | 0x2be1f0 | 96 octets live = dump |
| kmem_alloc_contig | 0x24dbe0 | 96 octets live = dump |
| kmem_free | 0x466af0 | 96 octets live = dump |
| pmap_extract | 0x573d0 | 96 octets live = dump |
| pmap_protect | 0x58570 | 96 octets live = dump |
| sched_pin | 0x231e10 | 96 octets live = dump |
| sched_unpin | 0x231e30 | 96 octets live = dump |
| smp_rendezvous | 0x1adaa0 | 96 octets live = dump |
| smp_no_rendevous_barrier | 0x1ad8b0 | 96 octets live = dump |
| icc_query_nowait | 0x448a10 | 96 octets live = dump |
| kernel_map | 0x22d1d50 | variable lue en mémoire (BSS) |
| sysent | 0x1102b70 | 96 octets live = dump |
| kernel_pmap_store | 0x1b2c3a0 | variable lue en mémoire (BSS) |
| Starsha_UcodeInfo | 0x0 | 0, alternative facultative absente |
| gpu_devid_is_9924 | 0x4ad480 | 96 octets live = dump |
| gc_get_fw_info | 0x4bbe30 | 96 octets live = dump |
| pml4pml4i | 0x1b2c390 | variable lue en mémoire (BSS) |
| dmpml4i | 0x1b2c394 | variable lue en mémoire (BSS) |
| dmpdpi | 0x1b2c398 | variable lue en mémoire (BSS) |
| eap_hdd_key | 0x26c4cf0 | offset source ; clé non exportée |
| edid | 0x275e148 | variable lue en mémoire (BSS) |
| wlanbt | 0x479930 | 96 octets live = dump |
| kern_reboot | 0x3a2bc0 | 96 octets live = dump |
| set_gpu_freq | 0x4ba970 | 96 octets live = dump |
| set_pstate | 0x4bcd40 | 96 octets live = dump |
| update_vddnp | 0x4baf10 | 96 octets live = dump |
| set_cu_power_gate | 0x4bb320 | 96 octets live = dump |
| pstate_before_shutdown | 0x3a31b0 | 96 octets live = dump |
| set_nclk_mem_spd | 0x4377d0 | 96 octets live = dump |

Autres offsets importants issus du SDK / header 1402 : Xfast_syscall 0x1c0 ; kmem_alloc 0x466920 ; allproc 0x1b28538 ; vmspace_acquire_ref 0x2f7cf0 ; vmspace_free 0x2f7b20 ; proc_rwmem 0x366d80. Les deux vmspace sont conservés comme valeurs de source, sans appel de validation fonctionnelle dans ce travail. Les 28 entrées du SDK et leurs lectures précédentes restent dans collection.json et offsets_1402.tsv.

Points de patch identifiés par désassemblage :

| Patch | RVA | Contexte constaté |
|---|---|---|
| protection kmem_alloc 1 | 0x4669ec | immédiat de `mov r9d, 3/7` pour vm_map_insert ; déjà 7 sur cette session |
| protection kmem_alloc 2 | 0x4669f4 | immédiat du `push 3/7` ; déjà 7 sur cette session |
| pstate avant shutdown | 0x3a31b0 | immédiat de `mov edi, 1`, instruction commençant à 0x3a31af, suivie d'un appel vers set_pstate 0x4bcd40 |

Le syscall 11 est déjà fourni par le HEN et son appel a été vérifié par le diagnostic. Le syscall 153 est nosys (RVA 0x1c07a0) avant armement ; le chargeur refuse de remplacer un autre handler.
L'ICC à 0x448a10 référence la chaîne `icc_query_nowait`, le chemin source scesb/icc/icc.c et le message `ICC %02x-%02x nowait`. kmem_alloc référence directement kernel_map et les vm_map_* du SDK. sched_pin/sched_unpin modifient le champ de pinning du thread ; snprintf présente l'assemblage de va_list et le terminateur NUL attendus. Ces éléments ajoutent une cohérence sémantique aux signatures.

## ACPI, écran et microcodes

Le RSDP et les tables XSDT, RSDT, FACP, DSDT, APIC, MCFG et SSDT ont été récupérés à leurs adresses physiques via le direct map. Les checksums des tables ACPI contrôlables et du RSDP sont valides ; le FACS, qui n'utilise pas ce checksum, est aussi conservé. Aucun octet des tables de la console n'a été modifié pendant cette collecte.
`test_acpi.py` reconstitue une fenêtre physique de test avec ces tables, exécute fix_acpi_tables de la source sur cette copie sous AddressSanitizer, puis recontrôle les racines, les tables réécrites et l'IVRS ajouté : PASS.
EDID : en-tête valide, checksum du bloc de base valide, 1 bloc d'extension indiqué. Les octets lus sont conservés dans linux1402_verification.json.
Les en-têtes GPU sélectionnés par le chemin Liverpool ont été contrôlés : RLC 6144, SDMA0/1 4200 chacun, CE 8576, PFP/ME/MEC1/MEC2 16768 octets chacun. Les huit tailles correspondent à ce qu'attend l'extracteur du chargeur ; les pointeurs de blobs sont canoniques. Les microcodes eux-mêmes ne sont pas publiés séparément par cette collecte.

## Fichiers Linux et test exécuté sur la PS4

Le noyau annonce `7.3.3-Strawberry-General-ThinLTO+`, build #4 du 13 novembre 2026. Il possède un en-tête bzImage HdrS valide, protocole 0x20f, xloadflags 0x63, cmdline_size 2047. L'initramfs gzip a été décompressé et son CPIO parcouru (175 entrées). Sa fonction de secours `ps4_rescue` évite de lancer automatiquement une installation de distribution.

| Fichier interne | Taille vérifiée | CRC32 exécuté sur la PS4 | SHA256 du fichier local correspondant |
|---|---:|---|---|
| bzImage | 20718592 | 0x7fccbf20 | b451efdde5bc00c7602f9908e97ea84002775253da960e601d0857776eb61f4e |
| initramfs.cpio.gz | 12595590 | 0x7b56d686 | cc776db2e71b8ad4137c555b249de32f8a2aeb67056094d5ce6097cecb30c2d5 |
| bootargs.txt | 203 | 0xdde39c97 | 6ce60e4c87ad8ca4fc0341fc3a0e22a575f3c63be38fccb29978fde48c48d33d |

Le diagnostic natif preflight.elf a été envoyé via l'interface PROC_ELF de ps4debug dans fs_cleaner.elf (PID 54 lors des essais). Les entrées pthread utilisées par l'injecteur ont été contrôlées dans libkernel_sys.sprx avant l'injection. Le diagnostic s'exécute comme uid 0, vérifie le noyau via le syscall 11, lit les fichiers complets et écrit un journal. Il n'installe pas de syscall et ne demande pas de redémarrage.

Dernier journal récupéré :

```text
PS4_1402_PREFLIGHT_V1
UID 0x0000000000000000
CPUID_SIGNATURE 0x0000000000710fc0
CPU_BRAND DG1701SNF87IG                                  
USER_SUBID 0x0000000000040100
SELF_FIRMWARE 0x000000000000057a
KEXEC_SYSCALL_RETURN 0x0000000000000000
BASE 0xffffffffc7114000
GUARD_RESULT 0x0000000000000000
FILE /data/linux/boot/bzImage
SIZE 0x00000000013c2400 CRC32 0x000000007fccbf20
FILE /data/linux/boot/initramfs.cpio.gz
SIZE 0x0000000000c03186 CRC32 0x000000007b56d686
FILE /data/linux/boot/bootargs.txt
SIZE 0x00000000000000cb CRC32 0x00000000dde39c97
PREFLIGHT_OK
```

Le contrôle CRC32 ne doit pas être présenté comme un SHA256 distant : seuls les SHA256 locaux ont été calculés ici. Le chargeur recalcule aussi les CRC32 en mémoire sur les fichiers qu'il s'apprête à charger, après lecture, et refuse une autre paire. Sa sélection de fichiers est limitée au chemin interne contrôlé, sans priorité USB implicite.

## Corrections et tests du portage

- Sélection effective du kexec 1402 ; un seul blob embarqué pour ce build spécialisé.
- Gardes de code générées depuis les lectures vérifiées, contrôle chipset, direct map, EDID/ACPI côté hôte et refus d'un syscall 153 occupé.
- Chargement borné, gestion correcte des erreurs signées de read, fichiers fermés et buffers terminés par NUL.
- CRC complets et en-têtes de boot vérifiés avant les patches.
- Sauvegarde/restauration exactes de CR0 et des flags d'interruption ; absence de red zone/SIMD dans les chemins noyau compilés.
- Suppression de la boucle infinie de réallocation ; suivi de l'adresse vm_map originale et de la taille pour le nettoyage, au lieu de libérer un alias direct-map ou une taille réduite d'initramfs.
- Retour d'erreur correct de kernel_init sur base invalide.
- Armement kexec contrôlé avant création du thread d'arrêt ; aucun arrêt demandé sur une erreur signalée. Le délai d'arrêt est de huit secondes après l'armement.
- Lecture sysctl du southbridge via les appels directs name2oid puis __sysctl, sans charger une seconde variante de libkernel ; gestionnaires de signaux du processus conservés.
- errno alloué sur quatre octets ; compilation reproductible avec les sources de syscalls locales.
- Journaux persistants de diagnostic et de chargeur ; fichier d'état écrit avant l'envoi. Aucune réinjection automatique d'une requête de lancement dont le résultat serait incertain.

Tests : 384 corruptions unitaires de signatures refusées ; mauvais southbridge, base non noyau et syscall occupé refusés. Tests d'allocation : retour d'échec, nettoyage sur échec de traduction physique, bonne adresse/taille libérée, rejet d'un free inconnu, capacité et réutilisation des slots. Replay ACPI sous AddressSanitizer : PASS. Compilation du blob et du chargeur, absence de symboles non résolus et de relocations : contrôlées. Le diagnostic réel retourne PREFLIGHT_OK. Ces tests ne remplacent pas l'observation d'un démarrage Linux.

## Déploiement et reprise

Les scripts Python s'exécutent sur le PC. Les ELF/BIN sont destinés à la PS4.

```sh
```

La cible reste la PS4 192.0.2.10 ; la mention PS3 dans le message de suivi a été traitée comme une coquille, compte tenu de tout le contexte et des accès observés.
Le mode diagnostic sauvegarde bootargs.txt, retire quiet, active loglevel=7 et ignore_loglevel, et ajoute ps4_rescue. Les args d'origine sont conservés localement et sur la console ; restore-bootargs permet de les remettre lorsque FTP Orbis est accessible.
Payloads déposés sous de nouveaux noms : `/data/payloads/linux-1402-belize2-checked.elf` et `.bin`. Ils ne remplacent pas linux-2048mb.bin existant. Dossier console : `/data/linux/portage-linux`.
Le script de déploiement contrôle les tailles FTP ; les CRC des images de boot sont, eux, effectivement exécutés sur la console. Les accusés de réception d'un payload sont distingués de son résultat et du démarrage effectif.

## Limites et observations encore nécessaires

La collecte des offsets requis par ce chargeur référencé et les contrôles préalables ont avancé jusqu'à un diagnostic réel réussi. La sélection 1402 et les erreurs d'intégration identifiées ont été corrigées. Le modèle commercial exact, la stabilité prolongée des périphériques Linux et l'installation d'une distribution complète ne sont pas démontrés par ces observations. L'absence de réseau après la tentative de bascule ne suffirait pas à prouver un démarrage réussi ni un échec : il faut une trace Linux, une réponse réseau Linux ou une observation de l'écran.
Aucun formatage, changement de firmware ou écriture dans la flash n'a été réalisé par ces scripts. Le portage réalise les patches RAM nécessaires uniquement lors du lancement boot autorisé.

Les catalogues et analyses historiques sont conservés pour la traçabilité. Leurs mentions « réseau inaccessible » décrivent d'anciens essais : les accès et lectures live ont fonctionné dans cette session. Les fichiers marqués .partial restent des téléchargements interrompus, sans validation d'intégrité.

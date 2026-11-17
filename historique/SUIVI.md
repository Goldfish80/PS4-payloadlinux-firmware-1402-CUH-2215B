# Suivi du portage PS4 — état visible

Dernière actualisation UTC : 2026-11-17T04:06:44.296929+00:00

**Débogage de l’allocation mémoire ; aucun démarrage Linux confirmé.**

## Où consulter le travail

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
9. Cette alternative ne peut pas être branchée seule : l’ancien thunk suppose une plage physique unique pour le noyau et l’initramfs. Une adaptation de la relocalisation par pages est en préparation. Le planificateur de copies a passé **20 000 tests aléatoires**, chevauchements, cycles et bornes mémoire compris. **Il n’est pas encore intégré ni validé par un démarrage PS4.**

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

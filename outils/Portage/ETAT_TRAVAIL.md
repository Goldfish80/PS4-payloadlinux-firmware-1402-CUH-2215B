# État de reprise — objectif actif


Travail acquis :
- Fork récent jclass/ps4-linux-loader, commit 741b0ef96780afbb262ea7ea3958bcb3dcd09067, conservé dans Scout/upstream/linux-loader-1402. Table PS4_14_02 trouvée : 33 entrées, 25 fenêtres de 96 octets live identiques au dump ; BSS lue, UcodeInfo facultatif 0, clé HDD non exportée.
- Belize2 A0 confirmé par chaîne sysctl_oid -> handler -> global 0x21d279c = 0x40100 et par diagnostic userland __sysctl. Direct map ffffabbb00000000. CPUID 0x710fc0, brand DG1701SNF87IG. ACPI 8 APIC actifs. Tables ACPI et FACS récupérées et sommes valides ; replay natif fix_acpi_tables + ASan réussi.
- Huit en-têtes microcodes GPU tailles conformes, EDID valide. Noyau Strawberry 7.3.3, bzImage 20718592 CRC 7fccbf20, initramfs 12595590 CRC 7b56d686.
- preflight.elf réellement injecté avec succès dans fs_cleaner.elf PID 54 via ps4debug PROC_ELF. Lecture entière des fichiers et gardes => PREFLIGHT_OK. Dernier log contient USER_SUBID=0x40100.
- Travail corrigé dans Portage/loader (worktree branche local/ps4-1402-checked). Défaut upstream principal : blob 1402 absent de l'intégration AIO malgré les offsets. Build maintenant restreint 1402/Belize2, signatures/CRC vérifiés, paramètres de lecture robustes, ordre du redémarrage corrigé, registres préservés, alloc/free corrigés, logs persistants. Syscall 153 doit être nosys ; ne pas réinjecter si déjà armé.
- Tests gardes (384 corruptions), contexte, alloc/free, ACPI ASan PASS. ELF/BIN compilés ~37/30 KiB. Archive complète 18,5 Mo déposée sur console /data/linux/portage-linux/portage-linux-complet.zip avec taille FTP vérifiée.

À poursuivre :
1. Après dernières modifications host, actualiser l'archive/rapport via Portage/update_report.py si utile.
2. Démarrer capture UDP 6666 avec Portage/capture_netconsole.py.
3. Lancer python Portage/portage_linux.py boot --diagnostic --netconsole '6665@192.0.2.10/eth0,6666@192.0.2.10/ac:81:12:af:3c:8d'. L'adresse/MAC PC sont observées sur wlan0. Kernel CONFIG_NETCONSOLE=y et SKY2=y. Netconsole ne prouve rien si Ethernet non connecté ; ne pas confondre absence de logs avec échec.
4. Le script déploie sous noms neufs, sauvegarde bootargs, relance diagnostic, recontrôle, envoie chargeur, récupère loader.log jusqu'à KEXEC_ARMED. Le payload demande l'arrêt normal huit secondes après armement. Pas de formatage/installation automatique : ps4_rescue pour premier boot.
5. Confirmer Linux avec netconsole et/ou observation HDMI. Une acceptation PROC_ELF / KEXEC_ARMED ne suffit pas à déclarer un boot Linux réussi. Si échec avant armement, lire logs et diagnostiquer, ne jamais relancer une requête de lancement au résultat inconnu.


## Mise à jour après essai (16/11, après 05:25 UTC)

Premier boot réellement envoyé. loader.log confirme firmware/subid/fichiers/CRC, KERNEL_STAGE_RESULT=0, puis KEXEC_LOAD_RESULT=12 (ENOMEM). Aucun reboot demandé ni ICC hook armé. Le syscall 153 a ensuite été restauré à nosys par un callback contrôlant que son handler appartient bien à notre blob ; le blob a été libéré. Preuve debug actuelle : slot153 -> base+0x1c07a0.

Le premier diagnostic d'alloc s'est arrêté à l'écriture d'une sortie BSS utilisateur non résidente depuis le noyau. Deuxième version place les sorties en .data et les touche en userland avant syscall11 ; elle termine. Résultats réels : kmem_alloc_contig 16Ko -> PA2ed04000, 64Ko -> PA59e30000, 1Mo -> PA00100000 ; 20,7Mo et 12,6Mo -> NULL. pmap_extract fonctionne (physique noyau07114000), pmap_root=ffffabbb09a14000, physmem_pages162947, realmem_pages654080. Le problème constaté est donc la contiguïté physique des grosses réservations, pas un manque démontré de RAM totale ni un mauvais offset pmap.

Nouvelle piste active : tester kmem_alloc (VA continue / PA discontinues) pour les grosses images via Portage/probe_virtual_allocator.py ; fichier console virtual-allocator.log à récupérer. S'il fonctionne, adapter la bascule avec un plan de copies par pages physiques (scatter-gather) exécuté dans le thunk bas mémoire après arrêt des CPU et passage sur des tables identity mappant 16GiB. Noyau final à 0x6000000 - setup_bytes ; setup_sects31 -> setup_bytes0x4000 ; initrd final0x20000000, hors init_size0x3236000. Construire un plan de déplacement résistant aux chevauchements/cycles avec une page scratch ; seulement liste64Ko et scratch16Ko physiquement contiguës, petites allocs déjà démontrées. Tester le plan indépendamment (cycles, overlaps, bornes) et la séquence ASM avant tout boot. Les images de staging deviennent des allocations kmem_alloc ; BP/cmdline restent de petites allocations contiguës.


# Écoute distante de la PS4

2026-11-16 : service TCP 3232 accessible, flux réel reçu (journaux Orbis/ShellCore). Capture active dans orbis_tcp3232.log ; script réutilisable Portage/capture_orbis_log.py avec reconnexion.

Autres services constatés : FTP 2121, BinLoader 9090. ps4debug 744 fermé lors de cette vérification. Le BinLoader reçoit des exécutables ; ce n’est pas un flux de journaux.

Capture Linux distincte : UDP 6666, script capture_netconsole.py. Aucun paquet reçu lors du premier essai. Elle dépend de l’initialisation du pilote réseau Linux et ne prouve pas l’absence d’exécution avant cette étape.

Fichiers récupérés via FTP dans apres_extinction/. sce_coredumps vide ; rpi_nextgen_crash.txt vide ; ces seuls constats ne démontrent pas l’absence de crash noyau. Journal système /data/sce_logs/log.bin en cours de récupération.

Limite : lorsque le réseau Orbis s’arrête, son flux TCP cesse. Un UART matériel serait indépendant du réseau, mais aucun adaptateur série connecté n’est établi ici. Ne pas prétendre disposer de cette capture matérielle.

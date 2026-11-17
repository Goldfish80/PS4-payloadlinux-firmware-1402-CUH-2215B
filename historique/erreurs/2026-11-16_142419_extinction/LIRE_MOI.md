# Échec de démarrage Linux : extinction de la PS4

Essai du 16 novembre 2026, lancé à 14:24:19 UTC.

- Préparation : firmware/signatures/CRC conformes ; KERNEL_STAGE_RESULT=0 ; KEXEC_LOAD_RESULT=0 ; KEXEC_ARMED.
- J’ai observé : la PS4 s’est éteinte, sans affichage Linux.
- Réseau : services Orbis disparus après arrêt, aucun paquet Linux netconsole reçu.
- Conclusion : démarrage Linux non réussi ; point exact de défaillance inconnu. L’armement ne démontre pas l’exécution du hook ni celle de Linux.
- Les payloads de ce dossier sont ceux relus sur la console après cet essai et comparés au manifeste déployé. La version source compilée ensuite contient des diagnostics supplémentaires : ne pas confondre les deux.
- orbis_tcp3232.log commence APRÈS le redémarrage suivant : il ne capture pas rétroactivement la première extinction. sce_log.bin est une copie brute du journal disque récupéré après coup ; son contenu doit être analysé avant attribution à cet incident.
- Aucun coredump trouvé dans /data/sce_coredumps ; cela ne suffit pas à exclure un crash noyau.

Voir ESSAI_MATERIEL_SG.md et operation_20261116_142419.json pour les détails.

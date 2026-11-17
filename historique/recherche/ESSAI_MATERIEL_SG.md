# Essai matériel du chargeur par pages

2026-11-16 — opération operation_20261116_142419.json.

Payload ELF SHA256 : 5dcb3d2909b1647bc3a343e1a9ee09a4391125bd52758099410eeb97af8c7832.

Diagnostic préalable complet PASS. Payload accepté par le transport puis exécuté : firmware 1402, Belize2 A0, CRC fichiers corrects, KERNEL_STAGE_RESULT=0, KEXEC_LOAD_RESULT=0, KEXEC_ARMED. Arrêt normal demandé après huit secondes.

Cela confirme le chargement et l’armement ; ce n’est pas encore une confirmation d’exécution Linux. Capture netconsole active, observation écran demandée.

Corrections finales avant essai : conversions direct map par addition/soustraction ; conserver telles quelles les adresses déjà physiques du stub, des paramètres et de la ligne de commande. Sources compilées et diagnostic console revérifiés avant envoi.

Après la demande d’arrêt : ports 744/2121/22 refusés, trois pings sans réponse, aucun paquet netconsole reçu à ce stade. Ces observations ne prouvent ni un boot Linux ni une panne ; attente de l’écran/LED pour déterminer l’état réel. La console ne fournit plus son FTP, donc le compte rendu final reste local jusqu’au retour de cet accès.

J’ai observé : « la ps4 a juste fermer ». Aucun Linux visible. L’essai est donc classé ÉCHEC DE DÉMARRAGE OBSERVÉ, malgré chargement et armement réussis. Le point exact de défaillance reste inconnu. Analyse statique : fonction ICC 0x448a10 appelée depuis des routines construisant des messages d’alimentation (0x1d9730 et 0x1d97d0), sans preuve que le hook ait été exécuté lors de cet essai. Une validation par relecture du saut installé est ajoutée pour le prochain essai.

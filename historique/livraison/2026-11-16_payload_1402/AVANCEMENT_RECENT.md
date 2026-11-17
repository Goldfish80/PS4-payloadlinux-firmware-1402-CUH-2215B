# Avancées récentes — PS4 Linux

- Allocation contiguë initiale échouait ; le chargement par pages a permis `KEXEC_LOAD_RESULT=0`.
- Corrections direct-map validées par test réel sur 2042 pages, y compris au-dessus de 4 Gio.
- Deuxième essai observé dans les journaux Orbis : firmware 14.02, Belize2, préparation noyau/initramfs, plan de 2040 copies, relecture du saut d’arrêt PASS, chargeur armé.
- La phase de création écrit une image d’environ 16 Gio par défaut, progresse de 0 à 25 %, puis l’image est formatée ext4 et l’archive Debian décompressée. L’installateur annonce quelques minutes ; la console doit rester allumée.
- Une vérification du saut d’arrêt a été ajoutée après le lancement observé. **Le payload joint est cette compilation plus récente et n’a pas encore été envoyé ni essayé sur la PS4.**
- Le réseau de la PS4 s’est absenté pendant l’installation. Les fichiers sont présents localement ; l’envoi vers le dossier de la console attend que FTP/connexion Linux soit disponible.

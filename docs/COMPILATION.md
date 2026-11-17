# Compilation du payload complet sous Linux

J’utilise GCC, GNU binutils, Make et yasm. Les en-têtes FreeBSD et la petite bibliothèque nécessaires sont fournis avec le chargeur. La compilation propre a été vérifiée avec l’environnement Linux de préparation ; le journal de validation précise les résultats.

Depuis une copie neuve des sources :

```sh
cd source/ps4-linux-loader/linux
make payloads/linux-2048mb.elf payloads/linux-2048mb.bin
sha256sum payloads/linux-2048mb.elf payloads/linux-2048mb.bin
```

Le Makefile limite `FIRMWARES` à `1402`. Les gardes complètes sont incluses : aucune reconstruction manuelle des signatures n’est nécessaire.

Empreintes reproduites :

```text
3e298e504d2e4ce328a54ded0c06ddac281996f3598856e9699bf51f7488c380  linux-2048mb.elf
2206a6d8bec05a5fc6100dcb3a4a921536f4f0b58a27b611f0a8e3ca9f777350  linux-2048mb.bin
```

La correspondance de l’ELF a été vérifiée octet pour octet avec celui conservé de l’essai. Une autre version du compilateur peut produire des octets différents. Les avertissements d’assemblage sur `lret` et le segment RWX du blob kexec sont consignés ; la compilation termine correctement.

Les scripts de recherche et de déploiement sont conservés pour transparence. Les adresses d’exemple sont documentaires et les chemins de travail ont été neutralisés ; je les configure pour mon environnement avant une utilisation. Les scripts de diagnostic ne sont pas requis pour compiler le chargeur.

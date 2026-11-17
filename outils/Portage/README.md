# PS4 14.02 / Belize2 A0 — chargeur contrôlé

Cible observée : 192.0.2.10, ps4debug TCP 744, FTP GoldHEN TCP 2121.
Les scripts Python s'exécutent sur le PC. Les fichiers ELF/BIN s'exécutent sur la PS4.

Le code vient de la copie préservée du chargeur d'ArabPixel/rmuxnet :
https://github.com/jclass/ps4-linux-loader, commit
741b0ef96780afbb262ea7ea3958bcb3dcd09067.
Les licences et attributions des sources sont conservées dans `loader/`.

## Utilisation depuis ce PC

```sh
```

`check` relit la compatibilité et exécute le petit diagnostic : aucune écriture de code noyau ni demande de redémarrage. Il crée un thread de diagnostic dans fs_cleaner via l'interface ELF de ps4debug et écrit son journal dans `/data/linux/portage-linux/preflight.log`.
`deploy` compile, dépose le payload sous un nouveau nom, contrôle la taille des transferts et exécute le diagnostic.
`boot` effectue les contrôles, puis envoie le chargeur via ps4debug. Après armement réussi de kexec, le payload demande un arrêt normal huit secondes plus tard pour passer sous Linux. Un accusé de réception réseau seul ne constitue pas une preuve de démarrage Linux.

`--diagnostic` sauvegarde les arguments d'origine, rend les messages du noyau visibles et demande le shell de secours de l'initramfs avec `ps4_rescue`. Il ne lance pas l'installation d'une distribution ni le formatage d'un disque.

Pour remettre les derniers arguments sauvegardés, lorsque le FTP Orbis est de nouveau accessible :

```sh
```


## Conditions de ce build

Firmware 1402, Belize2 A0 (`hw.sce_subsys_subid = 0x40100`). Le modèle commercial précis n'est pas déduit de ce seul identifiant.
Le chargeur utilise uniquement `/data/linux/boot` et la paire contrôlée :

| Fichier | Taille | CRC32 |
|---|---:|---|
| bzImage | 20718592 | 7fccbf20 |
| initramfs.cpio.gz | 12595590 | 7b56d686 |

Le noyau est Strawberry 7.3.3 General ThinLTO. Changer cette paire exige de mettre à jour les constantes de vérification du chargeur après validation des nouveaux fichiers. Les CRC32 sont calculés sur les fichiers entiers ; les SHA256 locaux sont conservés dans les rapports.
La VRAM par défaut est 2048 Mo ; le mécanisme `vram.txt` du chargeur reste disponible.

Les adresses absolues dépendent du démarrage courant. Le payload recalcule la base avec LSTAR, contrôle les signatures, le southbridge et le syscall 153 avant les modifications. Il refuse de remplacer un syscall 153 déjà occupé.

## Corrections du chargeur

- Intégration effective du blob kexec 1402, absent de la sélection de l'AIO préservé malgré la table d'offsets présente.
- Contrôle des signatures et fichiers avant les patches ; aucun redémarrage demandé sur un échec signalé par kexec.
- Armement terminé avant création du thread d'arrêt ; journal persistant `loader.log`.
- Chargements de fichiers bornés, erreurs de lecture signées, fermetures et chaînes terminées par NUL.
- Restauration de CR0 et des flags d'interruption à leur valeur d'entrée.
- Absence de boucle de nouvelle allocation infinie ; libération par l'adresse vm_map et la taille initiales, non par l'alias direct-map.
- Lecture sysctl du southbridge sans charger une autre variante de libkernel dans le processus cible ; conservation de ses gestionnaires de signaux.
- Stockage correct d'errno sur 4 octets, compilation sans red zone ni registres SIMD dans les chemins noyau, sources de syscalls locales conservées lors de `clean`.

## Vérifications reproductibles

```sh
```

Les tests couvrent les signatures altérées et refus de contexte incorrect, les échecs d'allocation et leur nettoyage, puis la réécriture réelle des tables ACPI de cette console sous AddressSanitizer.
Le diagnostic ELF a été exécuté et a retourné `PREFLIGHT_OK` avec les CRC de la paire présente sur la PS4. Les résultats ultérieurs de lancement et les limites d'observation se trouvent dans les journaux d'opération et le rapport complet.

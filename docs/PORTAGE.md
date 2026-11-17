# Dossier technique du portage

## Cible

J’ai limité l’essai à ma PS4 Slim CUH-2215B, firmware **14.02**, Belize2 A0 (`0x40100`), CPUID `0x710fc0`, profil VRAM 2048 Mo. Le noyau Linux utilisé est `7.3.3-Strawberry-General-ThinLTO+`. Les noms internes `1402` et `PS4_14_02` désignent ce firmware.

## Offsets et signatures

Les tableaux conservés donnent les RVAs, les adresses relevées et les signatures d’instructions. Le travail initial identifie 33 entrées et compare 25 fenêtres de 96 octets entre capture et mémoire relevée. Une concordance de signature vérifie la compatibilité des octets ; elle ne démontre pas à elle seule le rôle sémantique de chaque fonction. Les adresses absolues d’une capture ne sont pas des constantes universelles : la base noyau et les mappings dépendent du démarrage.

Les gardes complètes utilisées à la compilation sont dans `source/ps4-linux-loader/linux/guards-1402.h`. Les captures noyau et leurs analyses sont dans `dumps/`, et les tables ACPI, vérifications de firmware, relevés de microcodes et essais dans `historique/preuves/` et `historique/recherche/`.

## Échec initial et correction

Le diagnostic préalable vérifie firmware, southbridge, signatures et CRC des fichiers entiers. Le premier chargeur a préparé le noyau, puis `kexec_load` a échoué avec `12 / ENOMEM`. Les petites allocations contiguës réussissaient ; les tailles d’environ 20 Mo pour le noyau et 12 Mo pour l’initramfs échouaient avec les paramètres testés. Cela démontre un problème de grandes allocations contiguës dans ce contexte, pas un manque prouvé de mémoire totale.

J’ai remplacé le staging des grosses images par des allocations virtuellement contiguës. Le chargeur récupère les pages physiques et prépare un plan de copies gérant recouvrements et cycles avec une page temporaire. Les petites structures nécessaires à la transition conservent leurs contraintes physiques. J’ai corrigé la conversion des adresses physiques pour les pages au-dessus de 4 Gio et conservé les contrôles de bornes, les nettoyages d’erreur et les vérifications du hook d’arrêt.

Le relevé d’allocation simultanée porte sur 2042 pages, dont 224 au-dessus de 4 Gio. Le journal de l’essai réussi indique 2040 opérations de relocalisation, `KERNEL_STAGE_RESULT=0`, `KEXEC_LOAD_RESULT=0`, `KEXEC_ARMED` et une relecture correcte du saut installé. Ces marqueurs décrivent le chargeur ; le démarrage de Debian constitue l’observation Linux distincte.

## Tests et reproductibilité

Les tests conservés couvrent 20 000 plans aléatoires, les cycles, les recouvrements, les pages invalides, les adresses hautes, les bornes, la libération après échec et le codage du hook. Le test du thunk exécute sa boucle de copie extraite, mais n’émule pas la transition privilégiée CR3/GDT. Les résultats historiques ne prouvent pas la fiabilité de démarrages répétés sur d’autres machines.

Je fournis aussi les vérifications effectuées pour cette publication dans `docs/VALIDATION.md`.

## Réseau et affichage

Le premier démarrage est en terminal. J’utilise Ethernet pour installer NetworkManager, puis je configure le réseau avec `nmtui`. Les messages WLAN répétés ont un correctif de filtrage conservé dans `correctifs/wlan/` : neutralisation de `ignore_loglevel` et masque RLM limité. Ce filtrage agit sur les messages ; il ne constitue pas une réparation universelle du pilote.

Pour XFCE, la [procédure Wayland/labwc](XFCE.md) décrit le contournement de l’écran noir et le rôle de `swaybg`.

## Rapports historiques

Je conserve les échecs et étapes intermédiaires dans `historique/`. Un rapport daté peut annoncer qu’aucun démarrage n’est encore confirmé : c’est l’état de cette étape, pas la conclusion actuelle. Les archives internes ont été réassemblées pour la publication ; les anciennes empreintes décrivent les originaux. Les fichiers de capture partiels gardent leur suffixe `.partial`. Une capture appelée « full » conserve son nom historique ; sa couverture réelle se lit dans ses métadonnées.

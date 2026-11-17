# Linux sur PS4 — firmware 14.02 / CUH-2215B

**Expérimental — j’ai essayé ce portage uniquement sur ma PS4 Slim CUH-2215B en firmware 14.02.** Je ne garantis pas sa compatibilité avec une autre console, un autre southbridge ou un autre firmware.

Je publie ici le chargeur complet, son code source avec les signatures, les offsets, les dumps noyau disponibles, les outils de recherche, les diagnostics et les fichiers Linux. Le profil du payload est Belize2 A0 (`0x40100`), avec 2048 Mo réservés à la VRAM.

## Téléchargement

Les paquets complets et le payload sont dans les [releases](https://github.com/Goldfish80/PS4-payloadlinux-firmware-1402-CUH-2215B/releases/latest). Le paquet principal contient le payload ELF et BIN, les sources, les dumps, les offsets et les fichiers de démarrage Linux. L’archive du noyau Linux complet est proposée séparément. Chaque téléchargement possède une empreinte SHA-256.

## Premier démarrage : terminal uniquement

Au début, **il n’y a aucune interface graphique : seulement le terminal**. Je branche un câble **Ethernet** pour disposer du réseau et télécharger NetworkManager. Une connexion Ethernet sans adresse ne suffit pas : le réseau doit d’abord fournir une adresse par DHCP avec les outils disponibles dans l’image. Les étapes détaillées sont dans [Installation et réseau](docs/INSTALLATION.md).

```sh
sudo apt update
sudo apt install network-manager
sudo systemctl enable --now NetworkManager
nmtui
```

Je configure ensuite le Wi-Fi avec `nmtui` si nécessaire. Je garde Ethernet pendant cette préparation.

## XFCE et écran noir

L’installation de `xfce4` et LightDM seule n’a pas donné un bureau X11 utilisable dans mon essai : écran noir et erreur `Configure crtc 0 failed` avec `xrandr`. J’ai contourné ce problème en lançant **XFCE sous Wayland avec labwc**, puis en réglant la sortie avec `wlr-randr`. `swaybg` rétablit le fond d’écran. La [procédure XFCE](docs/XFCE.md) contient les commandes et les réglages conservés.

J’ai vérifié un rendu XFCE de 1920×1080, avec panneaux, icônes et fond d’écran. Cela ne prouve pas à lui seul l’affichage HDMI physique après un redémarrage. Un écran encore noir à ce stade demande un diagnostic DRM/HDMI distinct.

## Code source du payload

Je fournis le **[code source complet du payload](source/ps4-linux-loader/)**, y compris les gardes d’instructions dans [`guards-1402.h`](source/ps4-linux-loader/linux/guards-1402.h), la table firmware et le code kexec. Le code est directement consultable dans l’onglet Code de ce dépôt.

- [Entrée du chargeur](source/ps4-linux-loader/linux/main-aio.c)
- [Détection et offsets](source/ps4-linux-loader/linux/fw_offsets.h)
- [Noyau et allocations](source/ps4-linux-loader/linux/ps4-kexec-common/kernel.c)
- [Staging par pages](source/ps4-linux-loader/linux/ps4-kexec-common/reloc_stage.c)
- [Planification des copies](source/ps4-linux-loader/linux/ps4-kexec-common/reloc_plan.c)
- [Bascule assembleur](source/ps4-linux-loader/linux/ps4-kexec-common/linux_thunk.S)
- [Compiler et vérifier](docs/COMPILATION.md)

## Résultat du portage

Les grosses allocations physiquement contiguës échouaient avec `ENOMEM`. J’ai utilisé des allocations virtuellement contiguës et adapté la relocalisation pour copier les pages physiques, y compris au-dessus de 4 Gio. Le journal de l’essai réussi contient `KERNEL_STAGE_RESULT=0`, `KEXEC_LOAD_RESULT=0`, `KEXEC_ARMED` et la vérification du saut du hook d’arrêt. Debian a ensuite démarré.

Une compilation propre des sources complètes reproduit **octet pour octet** le payload ELF conservé de cet essai :

```text
3e298e504d2e4ce328a54ded0c06ddac281996f3598856e9699bf51f7488c380
```

## Contenu et documentation

| Dossier | Contenu |
| --- | --- |
| `source/` | Sources complètes du chargeur |
| `payload/` | Payload firmware 14.02, ELF et BIN |
| `offsets/` | RVAs, adresses relevées, signatures et gardes |
| `dumps/` | Captures noyau, cartes mémoire, symboles et analyses |
| `outils/` | Collecte, diagnostics, tests et outils du portage |
| `linux/` | Noyau, initramfs, configuration et images d’installation, dans le paquet complet |
| `correctifs/` | Réglages XFCE, filtre des messages WLAN et travail HDMI expérimental |
| `historique/` | Rapports et archives datés, avec leurs conclusions de l’époque |
| `references/` | Sources de référence conservées |

Je décris les étapes techniques et leurs limites dans le [dossier de portage](docs/PORTAGE.md). Les [sources et crédits](docs/SOURCES.md) identifient les projets sur lesquels je me suis appuyé. Les inventaires SHA-256 correspondent aux fichiers publiés ; les anciennes empreintes dans les rapports historiques décrivent leurs captures d’origine.

Le manifeste complet vise le paquet téléchargeable ; les images volumineuses sont fournies dans les releases.

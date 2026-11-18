# DebianPS4V2 — XFCE et NetworkManager au démarrage

J’ai ajouté **DebianPS4V2** dans les [releases](https://github.com/Goldfish80/PS4-payloadlinux-firmware-1402-CUH-2215B/releases/tag/DebianPS4V2).
J’ai essayé cette version sur ma **PS4 Slim CUH-2215B, firmware 14.02, Belize2 A0**, et tout fonctionne pour moi.

NetworkManager est inclus et démarre automatiquement. Je n’ai plus besoin
d’un câble Ethernet pour installer NetworkManager ou XFCE : les paquets et
leurs dépendances sont fournis pour une installation hors ligne. Debian
démarre avec un bureau XFCE, avec ouverture automatique de ma session.

## Ce que je télécharge

- **DebianPS4V2-complet.zip** : le paquet complet, avec les payloads, le noyau,
  l’initramfs V2, les paramètres de démarrage, les paquets hors ligne, l’archive
  Debian de base et Mesa PS4.
- **DebianPS4V2.elf** : le payload pour le menu Payloads de GoldHEN.
- **DebianPS4V2.bin** : la variante pour un lanceur compatible BIN.
- **DebianPS4V2-sources.tar.gz** : les sources du chargeur V2, les scripts,
  les services et les correctifs.
- **SHA256SUMS** : les empreintes des fichiers de la release.

Les ELF/BIN seuls ne contiennent pas le système Debian ni les fichiers de
boot. Je prends le paquet complet pour disposer de tous les éléments.

## Copie des fichiers sur la PS4

Je décompresse `DebianPS4V2-complet.zip`. Le dossier `PS4/` reprend
l’arborescence à copier avec le FTP GoldHEN :

| Fichier du paquet | Destination sur la PS4 |
| --- | --- |
| `PS4/data/payloads/DebianPS4V2.elf` | `/data/payloads/DebianPS4V2.elf` |
| `PS4/data/payloads/DebianPS4V2.bin` | `/data/payloads/DebianPS4V2.bin` |
| `PS4/data/linux/DebianPS4V2/boot/bzImage` | `/data/linux/DebianPS4V2/boot/bzImage` |
| `PS4/data/linux/DebianPS4V2/boot/initramfs.cpio.gz` | `/data/linux/DebianPS4V2/boot/initramfs.cpio.gz` |
| `PS4/data/linux/DebianPS4V2/boot/bootargs.txt` | `/data/linux/DebianPS4V2/boot/bootargs.txt` |
| `PS4/data/linux/DebianPS4V2/boot/vram.txt` | `/data/linux/DebianPS4V2/boot/vram.txt` |
| `PS4/user/home/debianps4v2-offline.tar` | `/user/home/debianps4v2-offline.tar` |
| `PS4/user/home/debian-ps4-rootfs.tar.xz` | `/user/home/debian-ps4-rootfs.tar.xz` |
| `PS4/user/home/ps4-mesa.tar.xz` | `/user/home/ps4-mesa.tar.xz` |

Je garde ensemble le payload et les fichiers V2 : le chargeur vérifie la taille
et le CRC de son noyau et de son initramfs. Son profil réserve **2048 Mo de VRAM**.

## Premier lancement et installation existante

Je lance **DebianPS4V2.elf** depuis **GoldHEN → Payloads**. Le menu Multiboot
sélectionne Debian par défaut après dix secondes.

Si Debian est déjà installé, la V2 ajoute les composants à l’image existante,
sans la recréer. Sans installation Debian, l’archive de base fournie permet
de passer par l’installateur Multiboot. Je vérifie le support et l’espace
disponible dans cet installateur ; les premières installations créent une
image système sur le support choisi.

Au premier lancement de la V2, l’installation des paquets hors ligne peut
prendre plusieurs minutes. Je laisse la console allumée jusqu’au démarrage
du bureau. Les lancements suivants réutilisent les composants installés.

Pour un nouveau réseau Wi-Fi, je renseigne son mot de passe dans NetworkManager.
L’installation de XFCE et de NetworkManager ne demande pas de connexion Ethernet.

## Correctifs et ajouts repris

Je conserve les correctifs du portage 14.02 : sélection du blob kexec, gardes
firmware et Belize2, chargement par pages physiques, gestion des recouvrements
et des adresses au-delà de 4 Gio, conversions direct map corrigées et
vérification du saut d’arrêt.

J’ajoute l’initramfs dédié V2, XFCE, LightDM, le terminal XFCE, NetworkManager,
son applet et les outils Wi-Fi. Le service de première installation configure
le démarrage graphique et conserve le helper HDMI du kit PS4. Le noyau
Strawberry 7.3.3 reste identique à celui du portage.

## Vérification et diagnostic

Je vérifie les téléchargements avec `SHA256SUMS`. L’archive complète contient
aussi son propre manifeste et les empreintes de ses fichiers.

```sh
sha256sum -c SHA256SUMS
```

Dans Debian, je consulte les services et le journal d’installation avec :

```sh
systemctl status debianps4v2-firstboot NetworkManager lightdm
cat /var/log/debianps4v2-install.log
nmcli device status
```

Je fournis les sources V2 et les correctifs dans l’archive séparée. Les sources
du noyau inchangé restent disponibles dans la [release précédente](https://github.com/Goldfish80/PS4-payloadlinux-firmware-1402-CUH-2215B/releases/tag/v0.1.0-experimental-1402).

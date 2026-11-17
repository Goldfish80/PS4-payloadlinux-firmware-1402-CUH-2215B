# Installation et premier démarrage

J’ai testé uniquement ma PS4 Slim CUH-2215B, firmware **14.02**, southbridge Belize2 A0 (`0x40100`). Ce portage est expérimental.

## Fichiers à récupérer

Je télécharge le paquet complet dans les releases et vérifie son SHA-256. `payload/linux-1402-belize2-2048mb.elf` est le chargeur essayé ; sa version BIN est aussi incluse. Dans le paquet, `linux/` contient `bzImage`, `initramfs.cpio.gz`, `bootargs.txt`, la configuration du noyau, Mesa PS4 et l’image Debian conservée.

Le chargeur suppose un environnement PS4 déjà capable de lancer le payload et d’exécuter les appels nécessaires. Je ne présente pas ce paquet comme un exploit autonome du firmware.

Je conserve les noms attendus des fichiers de démarrage. Pour les chemins exacts, je consulte `main-aio.c` et les options de `outils/Portage/portage_linux.py --help`. Je garde mes données sauvegardées : le programme d’installation Linux peut modifier le support choisi. Les scripts historiques de préparation sont fournis pour examen ; leurs anciennes cibles et leurs anciennes sommes ne sont pas une procédure automatique actualisée.

## Terminal, Ethernet et NetworkManager

Au premier démarrage, **je dispose uniquement du terminal, sans bureau graphique**. Je branche Ethernet pour télécharger NetworkManager et les paquets suivants. Je vérifie le nom de l’interface et l’adresse attribuée :

```sh
ip -br link
ip -br address
ip route
```

Si Ethernet n’a pas encore d’adresse et que `dhclient` est disponible, je remplace `INTERFACE_ETHERNET` par le nom réellement affiché :

```sh
sudo ip link set INTERFACE_ETHERNET up
sudo dhclient INTERFACE_ETHERNET
```

Je vérifie aussi la résolution DNS. Une fois le réseau opérationnel :

```sh
sudo apt update
sudo apt install network-manager
sudo systemctl enable --now NetworkManager
nmtui
```

Dans `nmtui`, j’active la connexion souhaitée et je configure le Wi-Fi au besoin. Je vérifie les connexions avec `nmcli device status`. Si une configuration réseau existante gère déjà Ethernet, je la prends en compte avant de lui substituer NetworkManager.

## Bureau graphique facultatif

Je suis ensuite la [procédure XFCE](XFCE.md). Installer uniquement XFCE/LightDM ne suffit pas dans mon essai : la session X11 pouvait rester noire. Le contournement conservé utilise XFCE Wayland et labwc.

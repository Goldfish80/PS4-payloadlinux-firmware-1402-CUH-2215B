# XFCE : contournement de l’écran noir

## Ce que j’ai observé

Sur ma CUH-2215B, le chemin XFCE/X11/LightDM donnait un écran noir. `xrandr` refusait le mode demandé avec `Configure crtc 0 failed`. J’ai obtenu un bureau rendu en lançant XFCE sous Wayland avec labwc. Je distingue ce rendu d’une confirmation HDMI physique après redémarrage.

Si LightDM affiche déjà un écran noir, je reviens à une console avec `Ctrl+Alt+F2` avant de modifier la configuration.

## Installer les composants

Depuis le terminal, avec Ethernet et le réseau fonctionnels :

```sh
sudo apt update
sudo apt install xfce4 lightdm labwc xwayland wlr-randr swaybg grim
```

Je vérifie la présence de la session Wayland :

```sh
ls /usr/share/wayland-sessions/
startxfce4 --help
```

Je sélectionne la session **xfce-wayland** dans le gestionnaire de connexion, ou j’essaie depuis une console locale :

```sh
startxfce4 --wayland
```

La disponibilité de cette option dépend de la version de XFCE installée. Les relevés et la configuration réellement conservés sont dans `correctifs/xfce/`.

## Résolution et fond d’écran

Dans un terminal de la session Wayland :

```sh
wlr-randr
wlr-randr --output HDMI-A-1 --mode 1920x1080@60Hz
swaybg -i /usr/share/backgrounds/xfce/xfce-blue.jpg -m fill &
```

Je remplace le nom de sortie et le mode si `wlr-randr` affiche autre chose. Je n’utilise pas `xrandr` pour piloter la sortie du compositeur Wayland. `swaybg` corrige le fond noir qui persistait avant son lancement.

Pour appliquer les réglages à l’ouverture de session, depuis la racine du paquet :

```sh
install -Dm755 correctifs/xfce/config/ps4-wayland-display.sh "$HOME/.local/bin/ps4-wayland-display.sh"
mkdir -p "$HOME/.config/autostart"
sed "s|^Exec=.*|Exec=$HOME/.local/bin/ps4-wayland-display.sh|" \
  correctifs/xfce/config/ps4-wayland-display.desktop \
  > "$HOME/.config/autostart/ps4-wayland-display.desktop"
install -m644 correctifs/xfce/config/light-locker.desktop "$HOME/.config/autostart/light-locker.desktop"
```

J’ai désactivé le lancement automatique de `light-locker`, qui plantait dans `libX11` dans cet essai. La copie LightDM conservée sélectionne `xfce-wayland` et contient un réglage de connexion automatique propre à l’image de test ; je l’adapte avant de l’installer. Pour le choix de session seul :

```ini
[Seat:*]
user-session=xfce-wayland
```

## Limites

J’ai relevé `labwc`, `xfce4-session`, `xfce4-panel` et `swaybg` actifs, ainsi qu’un rendu 1920×1080 avec les panneaux, icônes et fond bleu. LightDM était activé pour le démarrage suivant, mais je n’ai pas confirmé cette configuration après redémarrage.

Si l’écran physique reste noir alors que le rendu existe, je poursuis le diagnostic dans DRM/HDMI. Le fichier `correctifs/noyau/ps4-bridge-experimental.patch` est un travail conservé, pas un correctif matériel validé à appliquer systématiquement. Le noyau livré reste celui identifié dans `linux/kernel.info`.

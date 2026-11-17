# PS4 Debian: écran noir avec XFCE


## État actuel

- Console : PS4 Slim CUH-2215B, Debian 13.7.
- Noyau observé : `7.3.3-Strawberry-General-ThinLTO+`.
- XFCE était installé, mais la voie X11/LightDM n'ouvrait pas une session XFCE utilisable. Le mode 1080p demandé avec `xrandr` échouait (`Configure crtc 0 failed`).
- La session `xfce-wayland` lancée avec labwc fonctionne : `labwc`, `xfce4-session` et `xfce4-panel` tournent. `wlr-randr` sélectionne `1920x1080@60Hz`.
- Une capture Wayland de 1920×1080 montre le bureau XFCE avec panneaux, icônes et fond bleu. Le bureau est donc rendu par XFCE; une capture ne prouve toutefois pas que le signal HDMI physique apparaît sur l'écran.

## Changements appliqués à Debian

- Paquets présents/ajoutés : `labwc`, `xwayland`, `wlr-randr`, `grim`, `swaybg`.
- LightDM est configuré pour ouvrir automatiquement la session `xfce-wayland` sous `debian`.
- LightDM est activé pour le prochain démarrage système. Lors du relevé, son unité était `inactive` tandis que l'ancienne session graphique restait active; aucun redémarrage de la console n'a été fait pour ne pas interrompre cette session.
- Un démarrage automatique XFCE applique le mode HDMI 1920×1080 à 60 Hz puis lance `swaybg` avec le fond XFCE. Cela contourne le fond noir que la capture affichait avant le lancement de `swaybg`.
- L'entrée de démarrage automatique `light-locker` est désactivée pour cet utilisateur. `light-locker` avait planté dans `libX11` pendant la session Wayland/Xwayland.

Les copies des réglages sont dans [`config/`](config/); les observations datées sont dans [`diagnostics/`](diagnostics/).

## Conclusion et limite

Le problème du bureau X11 est contourné en démarrant XFCE sous Wayland, avec labwc. Le fond noir dans la capture était aussi dû à l'absence de gestionnaire de fond Wayland; `swaybg` le corrige. Le réglage de résolution fonctionne dans le compositeur.

Si l'écran physique reste noir alors que cette session tourne, le problème restant se situe probablement plus bas, dans la sortie DRM/HDMI du noyau ou son pont HDMI. Un rapport GitHub documente ce symptôme après un modeset et une cause dans `ps4_bridge`, mais ses tests sont sur une CUH-12xx/Aeolia, pas sur cette CUH-2215B/Belize2 A0. Il ne faut donc pas appliquer son correctif noyau à cette console sans diagnostic spécifique.

## Références consultées

- [PS4 Linux Notes — dépannage écran noir](https://thevorkman.github.io/ps4-linux-notes/Guides/4.-Blackscreen-Troubleshooting) : recommande Wayland lorsque l'écran devient noir après le lancement d'un bureau X11; mentionne `startxfce4 --wayland`.
- [PS4 Linux Tutorial — problèmes post-installation](https://dionkill.github.io/ps4-linux-tutorial/issues) : conseille d'essayer Wayland quand le gestionnaire d'affichage ou le bureau X11 donne un écran noir.
- [aday1/ps4-hdmi-blackscreen](https://github.com/aday1/ps4-hdmi-blackscreen) : analyse un écran HDMI noir après modeset et `ps4_bridge`; matériel testé indiqué comme CUH-12xx, donc résultat non transposable directement à la CUH-2215B.

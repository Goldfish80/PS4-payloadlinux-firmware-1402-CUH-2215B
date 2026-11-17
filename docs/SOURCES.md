# Sources et crédits

Je me suis appuyé sur les projets suivants et je conserve leurs attributions dans les sources :

- Chargeur : `jclass/ps4-linux-loader`, état de référence `741b0ef96780afbb262ea7ea3958bcb3dcd09067`, avec les tables firmware attribuées aux sources conservées. Les modifications du portage et les gardes complètes sont dans `source/`.
- Noyau Strawberry PS4 Linux : https://gitlab.com/rmuxnet/linux.git, branche `ps4/7.3.3`, commit `4025a70665daa096374a9fec8ade87435547d0e8`. L’archive séparée contient l’arbre complet de référence ; la configuration et l’identification du binaire sont dans `linux/kernel.config` et `linux/kernel.info`.
- Debian, XFCE, labwc, Wayland, Mesa et les autres composants conservent leurs propres auteurs, notices et licences. Leurs fichiers d’origine sont conservés dans les sources et les archives correspondantes.

La copie de travail HDMI est publiée séparément dans `correctifs/noyau/`. Elle n’est pas présentée comme intégrée au noyau binaire essayé. Les références et les rapports datés complètent les détails de provenance.

# Sources complètes du payload

Je fournis le chargeur complet dans `ps4-linux-loader/`, avec les signatures d’instructions et les gardes du firmware **14.02**. Le profil essayé correspond uniquement à ma PS4 Slim CUH-2215B, Belize2 A0, VRAM 2048 Mo. Ce portage est expérimental.

La procédure de compilation et les empreintes reproduites sont dans `../docs/COMPILATION.md`. Le Makefile construit le profil 1402. Les documents upstream conservés décrivent aussi le projet de référence et ses autres cibles ; mes observations matérielles concernent uniquement cette console.

Je fournis séparément les sources complètes du noyau Linux utilisé dans les téléchargements de la release.

# Confrontation de la revue Astra au code actuel


Vérifié dans les sources actuelles :
- Makefile inclut reloc_plan.c et reloc_stage.c.
- kexec.c utilise kernel_alloc_stage pour noyau et initramfs, puis reloc_stage_prepare.
- linux_thunk.S contient la boucle de copie de pages.
- linux_boot.c construit 16 entrées de 1 Gio pour la nouvelle identité ; la boucle de 4 entrées correspond à l’ancien contexte.
- Les changements de fréquence GPU viennent après la préparation mémoire.

Ces changements de sources ne prouvent pas un démarrage matériel réussi.

Points toujours à valider :
- Deux grandes allocations conservées ensemble, avec la capacité complète des firmwares, contrôle de toutes les pages et du contenu.
- Traduction directe des adresses physiques élevées : les macros OR/masque actuelles sont à vérifier, leur validité ne découle pas du seul pmap_extract des buffers.
- Protection complète du code de bascule, de sa pile, de la liste, du scratch, des tables et paramètres ; cohérence du workspace init_size.
- Nettoyage sur les échecs, exécution réelle de la boucle assembleur et essai matériel instrumenté.

Tests supplémentaires ajoutés : cas de 2042 pages sans chevauchement et en cycle, et cycle de 4096 pages, avec adresses physiques au-delà de 4 Gio. Résultat enregistré séparément après exécution ; ne constitue pas un test matériel.

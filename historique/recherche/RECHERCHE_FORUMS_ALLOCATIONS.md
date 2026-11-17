# Recherche communautaire — allocations Linux PS4

Date : 2026-11-16. Recherche web, Reddit et issues GitHub.

## Cas directement pertinent

Projet Android TV PS4 : https://github.com/odiecay/android-tv-ps4
Architecture : https://github.com/odiecay/android-tv-ps4/blob/main/docs/DEVELOPMENT.md
Discussion : https://www.reddit.com/r/ps4homebrew/comments/1xe67zq/android_tv_for_ps4_android_tv_as_an_installable/

Le développeur rapporte une correction du code 12 : abandon des deux grandes allocations contiguës, stockage temporaire en morceaux et copie au changement de contexte mémoire. Son architecture décrit des morceaux de 2 Mio à 64 Kio, exclus des destinations finales, et une liste de copies parcourue après le changement de CR3. Le noyau protégé est placé à 96 Mio. C'est une source primaire décrivant son implémentation, pas une preuve de compatibilité avec notre firmware 14.02.

## Confrontation avec nos mesures

Nos allocations contiguës de 20 718 592 octets et de 12 726 774 octets (initramfs + firmwares) échouent pour les deux flags testés, 0x101 et 0x102. Les allocations virtuellement contiguës correspondantes réussissent. Cela rend la piste pertinente sans démontrer la cause exacte ni une pénurie globale de RAM.

Notre planificateur de déplacements de pages est en cours de validation. Il autorise des sources qui chevauchent des destinations et traite les cycles via une page temporaire, contrairement au schéma du projet cité qui évite les destinations pendant l'allocation. Ces approches nécessitent des validations différentes. Aucun démarrage réussi du nouveau chemin n'est établi.

## Cas à distinguer

https://www.reddit.com/r/ps4homebrew/comments/1wrkjvh/ps4linux_is_not_wanting_to_load_properly/
Problème rapporté de montage/root et USB après chargement : ne démontre pas un correctif de notre allocation avant démarrage.

https://github.com/fail0verflow/ps4-kexec/issues/15
Erreur de compilation en mode 32 bits : pas une solution ENOMEM.

Les résultats bruts des recherches d'issues sont conservés dans github_allocation_issues.json ; plusieurs sont hors sujet. Aucun offset ne doit être déduit de ces témoignages.

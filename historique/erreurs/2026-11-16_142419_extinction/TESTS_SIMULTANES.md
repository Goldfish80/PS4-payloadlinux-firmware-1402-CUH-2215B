# Tests supplémentaires — 2026-11-16

## Console réelle

`virtual-pair-probe.log` : PAIR_PASS, appel 0, gardes 0, 2042 pages, aucune adresse invalide ou dupliquée, 224 pages physiques au-delà de 4 Gio. Deux buffers gardés simultanément, remplis entièrement avec des motifs distincts puis vérifiés après toutes les écritures : 33456128 octets, zéro erreur. Deux libérations effectuées.

La traduction pmap de dmap+PA correspond à PA pour toutes les pages ; celle de dmap|PA échoue sur 224 pages. Correction PA_TO_DM par addition, DM_TO_ID par soustraction. Vérification locale de l’aller-retour pour toutes les pages de 16 Kio des premiers 16 Gio.

## Intégration simulée

`test_reloc_stage.py` sous ASan/UBSan (détection des fuites désactivée) : préparation à taille réelle avec 2042 pages sources au-delà de 4 Gio ; trois échecs d’allocation distincts ; échec de traduction ; contrôle des tailles et libérations ; annulation répétée ; rejets des bornes de décompression et d’initramfs. PASS.

Limites : modèle local d’allocateur/pmap, avec le véritable en-tête Linux du chargeur ; ne remplace pas l’exécution matérielle du chargeur ou de sa boucle assembleur. Aucune bascule vers Linux demandée pendant ces tests.

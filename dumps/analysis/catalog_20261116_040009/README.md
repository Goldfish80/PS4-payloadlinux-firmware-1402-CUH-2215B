# Catalogue statique PS4

Dump SHA256 : `bfe5b4efae4f025674dc6346eb327bd4b69edb42dbb15895177a6ea51d2ded39`.
Base dans le dump : `0xffffffffc7114000` ; entrée RVA `0x6a410`.

Extraction : 18507 chaînes ASCII terminées par NUL, 45038 relocations relatives,
13202 références exactes vers des chaînes et 21926 cibles distinctes dans des segments exécutables.
Les pointeurs de code sont des candidats, sans nom de fonction démontré.
Les références sont issues des relocations, pas d'un désassemblage des instructions.
Les chaînes peuvent aussi provenir de suites d'octets accidentellement imprimables.

Les adresses absolues concernent le dump historique, pas une session actuelle.
Les RVA tiennent compte des segments : un offset fichier n'est pas toujours un RVA.
La base de lien 0xffffffff82200000 est reprise des analyseurs locaux.
La comparaison des valeurs des slots avec la base du dump est fournie par ligne.
Les symboles et leurs noms sont effacés dans le dump (voir audit SCE).
Les constantes du protocole décrivent le code source local ; elles ne prouvent pas l'accès actuel.

Réseau : les essais TCP ont échoué avec EPERM dans cet environnement.
Aucune validation en direct ni modification de la PS4 effectuée.

Reproduction : `python Scout/host/offline_catalog.py` depuis le projet.
Diagnostic en direct depuis un terminal disposant de l'accès réseau :
`PS4_IP=192.0.2.10 PS4_PORT=744 python Scout/host/ps4_scout_master.py`.

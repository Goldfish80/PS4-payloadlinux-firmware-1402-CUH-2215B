# Vérifications de publication — 17 novembre 2026

Je reproduis le payload ELF à l’identique avec une compilation propre sous Linux. Le BIN produit correspond également à son empreinte documentée. Je conserve les entrées noyau et initramfs exactes attendues par les contrôles de taille et de CRC du chargeur.

J’ai exécuté à nouveau les tests suivants sur une copie isolée du code :

```text
PASS: 384 corrupted code bytes rejected; wrong southbridge, occupied syscall and non-kernel base rejected
```

```text
PASS: shutdown absolute jump readback; corruption rejected and original bytes restored; pin/unpin balanced
```

```text
PASS: 2042-page high-PA copies/cycle and 4096-page cycle; 20000 randomized page-copy plans, overlaps, cycles, duplicate/unaligned/out-of-range pages, scratch conflicts and output bounds
```

```text
PASS: real-size staging (2042 high-PA pages), allocation failures 1/2/3, mapping failure cleanup, repeated cancel, decompression and initrd bounds
```

```text
PASS: actual compiled thunk copy loop; 2042 pages / 33456128 bytes from >4 GiB; complete content verified; 2/3/64-page cycles and zero moves
```

Ces tests s’exécutent sur la machine de compilation ; ils ne constituent pas un nouvel essai matériel. Le seul matériel essayé reste ma PS4 CUH-2215B en firmware 14.02. La transition privilégiée complète et les démarrages répétés ne sont pas couverts par ces tests.

Je vérifie les fichiers publiés et le contenu décompressé des archives avant l’envoi. Les empreintes du manifeste décrivent cette édition publiée, y compris les archives réassemblées.

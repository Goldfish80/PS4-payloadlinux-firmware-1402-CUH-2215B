#!/usr/bin/env bash
set -Eeuo pipefail

WORK="$HOME/PS4/Linux/Multiboot"
TMP="$WORK/debian-download"
INDEX="https://images.linuxcontainers.org/images/debian/trixie/amd64/default"

echo "===================================="
echo "     PREPARATION LINUX POUR PS4"
echo "===================================="

# 1. Vérifier les outils
for cmd in curl sha256sum xz grep sort head timeout; do
    command -v "$cmd" >/dev/null || {
        echo "Commande manquante : $cmd"
        exit 1
    }
done

if ! command -v lftp >/dev/null; then
    sudo pacman -S --needed lftp
fi

cd "$WORK"

# 2. Vérifier les fichiers Multiboot déjà téléchargés
echo
echo "=== VERIFICATION MULTIBOOT ==="

for f in bzImage initramfs.cpio.gz bootargs.txt \
         linux-2048mb.bin ps4-mesa.tar.xz SHA256SUMS; do
    [[ -s "$f" ]] || {
        echo "Fichier manquant : $f"
        exit 1
    }
done

sha256sum -c SHA256SUMS

# 3. Télécharger le dernier Debian 13 AMD64
echo
echo "=== TELECHARGEMENT DEBIAN 13 ==="

SNAPSHOT=$(
    curl -fsSL "$INDEX/" |
    grep -oE '[0-9]{8}_[0-9]{2}:[0-9]{2}/' |
    LC_ALL=C sort |
    tail -n1 |
    tr -d '/'
)

[[ -n "$SNAPSHOT" ]] || {
    echo "Aucun snapshot Debian trouvé."
    exit 1
}

echo "Snapshot sélectionné : $SNAPSHOT"

mkdir -p "$TMP"

URL="$INDEX/$SNAPSHOT"

curl -fL --retry 3 "$URL/SHA256SUMS" \
    -o "$TMP/SHA256SUMS"

curl -fL --retry 3 "$URL/rootfs.tar.xz" \
    -o "$TMP/rootfs.tar.xz"

# Vérifier la somme du rootfs
SUM_LINE=$(
    grep -E '^[[:xdigit:]]{64}[[:space:]]+\*?rootfs\.tar\.xz$' \
    "$TMP/SHA256SUMS" | head -n1 || true
)

[[ -n "$SUM_LINE" ]] || {
    echo "SHA256 du rootfs introuvable."
    exit 1
}

printf '%s\n' "$SUM_LINE" |
    (cd "$TMP" && sha256sum -c -)

xz -t "$TMP/rootfs.tar.xz"

install -m 644 "$TMP/rootfs.tar.xz" \
    "$WORK/debian-ps4-rootfs.tar.xz"

# 4. Préparer les instructions XFCE
cat > "$WORK/INSTALLER-XFCE.txt" <<'EOF'
DEBIAN 13 SUR PS4 - PREMIER DEMARRAGE

Connexion réseau recommandée : Ethernet.

Après connexion à Debian :

sudo apt update
sudo apt install xfce4 lightdm

Choisir lightdm comme gestionnaire de connexion
si le programme pose la question.

Mesa PS4 est intégré automatiquement par
PS4 Multiboot lors de l'installation.
EOF

# 5. Vérifier l'espace libre (lecture manuelle)
echo
echo "=== ESPACE DISQUE PS4 ==="
echo "Consulte Paramètres > Stockage > Stockage système."

read -r -p "Go libres sur la PS4 (ou ? si installation USB) : " FREE

if [[ "$FREE" =~ ^[0-9]+$ ]] && (( FREE < 26 )); then
    echo "ATTENTION : moins de 26 Go libres."
    echo "Ne choisis pas une image interne de 16 Go."
    echo "L'installation USB reste une possibilité."
elif [[ "$FREE" =~ ^[0-9]+$ ]]; then
    echo "Espace suffisant pour une image interne de 16 Go."
else
    echo "Espace non vérifié : à contrôler avant installation."
fi

# 6. Connexion FTP GoldHEN
echo
echo "=== CONNEXION FTP ==="

read -r -p "IP PS4 [192.0.2.10] : " PS4_IP
PS4_IP="${PS4_IP:-192.0.2.10}"

[[ "$PS4_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || {
    echo "Adresse IPv4 invalide."
    exit 1
}

if ! timeout 4 bash -c "</dev/tcp/$PS4_IP/2121" 2>/dev/null; then
    echo "FTP inaccessible sur $PS4_IP:2121."
    echo "Vérifie que le FTP GoldHEN est activé."
    exit 1
fi

read -r -p "Utilisateur FTP [anonymous] : " FTP_USER
FTP_USER="${FTP_USER:-anonymous}"

read -r -s -p "Mot de passe FTP (vide si aucun) : " FTP_PASS
echo

echo
echo "=== FICHIERS A TRANSFERER ==="
ls -lh "$WORK"/bzImage \
       "$WORK"/initramfs.cpio.gz \
       "$WORK"/bootargs.txt \
       "$WORK"/linux-2048mb.bin \
       "$WORK"/ps4-mesa.tar.xz \
       "$WORK"/debian-ps4-rootfs.tar.xz

echo
echo "Les fichiers distants existants ne seront pas écrasés."
read -r -p "Confirmer le transfert vers $PS4_IP ? [o/N] " OK

[[ "${OK,,}" == "o" || "${OK,,}" == "oui" ]] || {
    echo "Transfert annulé."
    exit 0
}

# 7. Transférer vers les chemins officiels Multiboot
echo
echo "=== TRANSFERT FTP ==="

lftp -u "$FTP_USER","$FTP_PASS" -p 2121 "ftp://$PS4_IP" <<EOF
set ftp:ssl-allow no
set ftp:passive-mode yes
set cmd:fail-exit yes
set xfer:clobber no

mkdir -p /data/linux/boot
mkdir -p /data/payloads

put -O /data/linux/boot "$WORK/bzImage"
put -O /data/linux/boot "$WORK/initramfs.cpio.gz"
put -O /data/linux/boot "$WORK/bootargs.txt"

put -O /data/payloads "$WORK/linux-2048mb.bin"

put -O /user/home "$WORK/debian-ps4-rootfs.tar.xz"
put -O /user/home "$WORK/ps4-mesa.tar.xz"

bye
EOF

echo
echo "===================================="
echo "          TRANSFERT TERMINE"
echo "===================================="
echo "Debian rootfs et fichiers Linux envoyés."
echo "Instructions XFCE : $WORK/INSTALLER-XFCE.txt"
echo
echo "Prochaine étape : lancer linux-2048mb.bin"
echo "depuis le menu Payloads de GoldHEN."

#!/usr/bin/env python3

import socket
from pathlib import Path

payload = Path(
    "~/PS4/Linux/Scout/upstream/ps4debug-NG/ps4debug-ng.bin"
).expanduser()

if not payload.is_file():
    raise SystemExit(f"Payload introuvable : {payload}")

host = input("Adresse IP de ta PS4 : ").strip()
port = 9090

data = payload.read_bytes()

print(f"Payload : {payload.name}")
print(f"Taille : {len(data):,} octets")
print(f"Destination : {host}:{port}")

confirm = input("Envoyer le payload ? (oui/non) : ")

if confirm.lower() != "oui":
    raise SystemExit("Envoi annulé.")

try:
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.settimeout(30)
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)

    print("Transfert terminé.")

except OSError as error:
    print(f"ERREUR : {error}")
    raise SystemExit(1)

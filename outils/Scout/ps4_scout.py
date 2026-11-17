#!/usr/bin/env python3

import socket
import struct
import json
from pathlib import Path
from datetime import datetime, timezone

MAGIC = 0xFFAABBCC
PORT = 744

COMMANDS = {
    "VERSION": 0xBD000001,
    "FW_VERSION": 0xBD000500,
    "BRANDING": 0xBD000501,
    "PLATFORM_ID": 0xBD000502,
    "KERN_BASE": 0xBDCC0001,
    "PROC_LIST": 0xBDAA0001,
}

def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connexion interrompue")
        data.extend(chunk)
    return bytes(data)

def u16(sock):
    return struct.unpack("<H", exact(sock, 2))[0]

def u32(sock):
    return struct.unpack("<I", exact(sock, 4))[0]

def command(sock, cmd):
    sock.sendall(struct.pack("<III", MAGIC, cmd, 0))

def status(sock):
    result = u32(sock)
    if result != 0x80000000:
        raise RuntimeError(f"Erreur PS4 : statut 0x{result:08X}")

def main():
    ip = input("Adresse IP de la PS4 [192.0.2.10] : ").strip()
    if not ip:
        ip = "192.0.2.10"

    report = {
        "tool": "PS4 Linux Scout",
        "collection_date": datetime.now(timezone.utc).isoformat(),
        "console_ip": ip,
        "results": {}
    }

    print("\n=== PS4 LINUX SCOUT ===")
    print("Connexion à", ip, "...")

    try:
        with socket.create_connection((ip, PORT), timeout=8) as sock:
            sock.settimeout(10)

            # Version du protocole
            command(sock, COMMANDS["VERSION"])
            length = u32(sock)
            if length > 128:
                raise ValueError("Longueur de version invalide")
            report["results"]["protocol_version"] = exact(sock, length).decode(
                "utf-8", errors="replace"
            )

            # Identité du payload
            command(sock, COMMANDS["BRANDING"])
            length = u32(sock)
            if length > 1024:
                raise ValueError("Longueur de branding invalide")
            raw = exact(sock, length)
            parts = raw.decode("utf-8", errors="replace").split("\0", 1)
            report["results"]["payload_branding"] = parts[0]
            report["results"]["capability_level"] = (
                parts[1] if len(parts) > 1 else None
            )

            # Version du firmware
            command(sock, COMMANDS["FW_VERSION"])
            fw = u16(sock)
            report["results"]["firmware"] = f"{fw // 100}.{fw % 100:02d}"

            # Identification de la plateforme
            command(sock, COMMANDS["PLATFORM_ID"])
            report["results"]["platform_id"] = u16(sock)

            # Adresse de base du noyau
            command(sock, COMMANDS["KERN_BASE"])
            status(sock)
            kernel_base = struct.unpack("<Q", exact(sock, 8))[0]
            report["results"]["kernel_base"] = hex(kernel_base)

            # Liste des processus
            command(sock, COMMANDS["PROC_LIST"])
            status(sock)
            count = u32(sock)

            if count > 4096:
                raise ValueError(f"Nombre de processus anormal : {count}")

            processes = []

            for _ in range(count):
                entry = exact(sock, 36)
                name = entry[:32].split(b"\0", 1)[0].decode(
                    "utf-8", errors="replace"
                )
                pid = struct.unpack("<i", entry[32:36])[0]
                processes.append({"name": name, "pid": pid})

            report["results"]["process_count"] = count
            report["results"]["processes"] = processes

        output = Path("~/PS4/Linux/Scout/reports").expanduser()
        output.mkdir(parents=True, exist_ok=True)

        filename = datetime.now().strftime("scout_%Y%m%d_%H%M%S.json")
        destination = output / filename
        destination.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        print("\n========== RÉSULTATS ==========")
        for key, value in report["results"].items():
            if key != "processes":
                print(f"{key}: {value}")

        print(f"\nProcessus trouvés : {count}")
        for proc in processes[:20]:
            print(f"  PID {proc['pid']:>6}  {proc['name']}")

        if count > 20:
            print(f"  ... et {count - 20} autres")

        print("\n[OK] Rapport sauvegardé :")
        print(destination)

    except Exception as error:
        print("\n[ÉCHEC]", repr(error))
        print("Aucun résultat incomplet ne sera présenté comme valide.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3

import socket
import struct
import json
from pathlib import Path
from datetime import datetime, timezone

IP = "192.0.2.10"
PORT = 744
MAGIC = 0xFFAABBCC

def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("Connexion interrompue")
        data.extend(part)
    return bytes(data)

def u32(sock):
    return struct.unpack("<I", receive(sock, 4))[0]

def command(sock, cmd, body=b""):
    sock.sendall(struct.pack("<III", MAGIC, cmd, len(body)) + body)

def check_status(sock):
    status = u32(sock)
    if status != 0x80000000:
        raise RuntimeError(f"Erreur PS4 : 0x{status:08X}")

def read_string(data):
    return data.split(b"\0", 1)[0].decode(
        "utf-8", errors="replace"
    )

def get_process_info(sock, pid):
    command(sock, 0xBDAA000A, struct.pack("<I", pid))
    check_status(sock)

    data = receive(sock, 188)

    return {
        "pid": struct.unpack_from("<I", data, 0)[0],
        "name": read_string(data[4:44]),
        "path": read_string(data[44:108]),
        "titleid": read_string(data[108:124]),
        "contentid": read_string(data[124:188])
    }

def get_process_maps(sock, pid):
    command(sock, 0xBDAA0004, struct.pack("<I", pid))
    check_status(sock)

    count = u32(sock)
    if count > 10000:
        raise ValueError(f"Nombre de mappings anormal : {count}")

    maps = []

    for _ in range(count):
        entry = receive(sock, 64)

        start, end, offset, prot = struct.unpack_from(
            "<QQQQ", entry
        )

        maps.append({
            "start": hex(start),
            "end": hex(end),
            "offset": hex(offset),
            "protection": prot,
            "name": read_string(entry[32:64])
        })

    return maps

def main():
    report = {
        "tool": "PS4 Linux Scout v0.2",
        "date": datetime.now(timezone.utc).isoformat(),
        "ip": IP,
        "processes": [],
        "system_maps": {}
    }

    print("PS4 LINUX SCOUT v0.2")
    print(f"Connexion : {IP}:{PORT}")

    with socket.create_connection((IP, PORT), timeout=8) as sock:
        sock.settimeout(10)

        # Récupération des processus
        command(sock, 0xBDAA0001)
        check_status(sock)

        count = u32(sock)
        if count > 4096:
            raise ValueError("Nombre de processus anormal")

        raw_processes = []

        for _ in range(count):
            entry = receive(sock, 36)
            name = read_string(entry[:32])
            pid = struct.unpack_from("<i", entry, 32)[0]
            raw_processes.append({"name": name, "pid": pid})

        print(f"\nProcessus détectés : {count}")

        # Métadonnées détaillées
        for proc in raw_processes:
            try:
                info = get_process_info(sock, proc["pid"])
                report["processes"].append(info)
            except Exception as error:
                report["processes"].append({
                    **proc,
                    "error": str(error)
                })

        # Cartes mémoire des processus système sélectionnés
        targets = [
            p for p in raw_processes
            if p["name"] in (
                "SceShellCore",
                "SceShellUI",
                "SceSystemService"
            )
        ]

        for proc in targets:
            try:
                print(f"Analyse mémoire : {proc['name']}")

                maps = get_process_maps(sock, proc["pid"])

                report["system_maps"][proc["name"]] = {
                    "pid": proc["pid"],
                    "count": len(maps),
                    "maps": maps
                }

            except Exception as error:
                report["system_maps"][proc["name"]] = {
                    "error": str(error)
                }

    destination = Path(
        "~/PS4/Linux/Scout/reports"
    ).expanduser()

    destination.mkdir(parents=True, exist_ok=True)

    filename = datetime.now().strftime(
        "inventory_%Y%m%d_%H%M%S.json"
    )

    output = destination / filename

    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print("\n========== TERMINÉ ==========")
    print("Processus documentés :", len(report["processes"]))

    for name, data in report["system_maps"].items():
        print(name, ":", data.get("count", data.get("error")))

    print("\nRapport :", output)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("\nÉCHEC :", repr(error))

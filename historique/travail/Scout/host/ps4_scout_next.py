#!/usr/bin/env python3
"""Read-only inventory client for ps4debug-NG v1.3.x."""

import json
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_IP = "192.0.2.10"
PORT = 744
MAGIC = 0xFFAABBCC

CMD_VERSION = 0xBD000001
CMD_FW_VERSION = 0xBD000500
CMD_BRANDING = 0xBD000501
CMD_PLATFORM_ID = 0xBD000502
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INFO = 0xBDAA000A
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_FOREGROUND_APP = 0xBDDD0006
CMD_SUCCESS = 0x80000000


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        try:
            part = sock.recv(size - len(data))
        except socket.timeout as exc:
            raise TimeoutError(
                f"timeout après {len(data)}/{size} octets"
            ) from exc

        if not part:
            raise ConnectionError(
                f"connexion fermée après {len(data)}/{size} octets"
            )

        data.extend(part)

    return bytes(data)


def send_command(ip, command, body=b"", timeout=10):
    sock = socket.create_connection((ip, PORT), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(
        struct.pack("<III", MAGIC, command, len(body)) + body
    )
    return sock


def read_status(sock):
    status = struct.unpack("<I", recv_exact(sock, 4))[0]

    if status != CMD_SUCCESS:
        raise RuntimeError(f"statut PS4 0x{status:08X}")


def read_string_reply(ip, command, timeout=8):
    with send_command(ip, command, timeout=timeout) as sock:
        length = struct.unpack("<I", recv_exact(sock, 4))[0]

        if length > 4096:
            raise ValueError(
                f"longueur de chaîne invalide: {length}"
            )

        return recv_exact(sock, length)


def read_u16_reply(ip, command, timeout=8):
    with send_command(ip, command, timeout=timeout) as sock:
        return struct.unpack("<H", recv_exact(sock, 2))[0]


def get_kernel_base(ip):
    with send_command(ip, CMD_KERN_BASE) as sock:
        read_status(sock)
        return struct.unpack("<Q", recv_exact(sock, 8))[0]


def read_kernel_bytes(ip, address, length=64):
    # CMD_KERN_READ request = uint64 address + uint32 length.
    body = struct.pack("<QI", address, length)

    with send_command(
        ip, CMD_KERN_READ, body, timeout=8
    ) as sock:
        read_status(sock)
        return recv_exact(sock, length)


def get_process_list(ip):
    with send_command(ip, CMD_PROC_LIST, timeout=12) as sock:
        read_status(sock)

        count = struct.unpack("<I", recv_exact(sock, 4))[0]

        if count > 4096:
            raise ValueError(
                f"nombre de processus anormal: {count}"
            )

        raw = recv_exact(sock, count * 36)

    processes = []

    for i in range(count):
        entry = raw[i * 36:(i + 1) * 36]

        name = entry[:32].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        )

        pid = struct.unpack_from("<i", entry, 32)[0]

        processes.append({
            "name": name,
            "pid": pid
        })

    return processes


def get_process_info(ip, pid):
    body = struct.pack("<I", pid)

    with send_command(
        ip, CMD_PROC_INFO, body, timeout=8
    ) as sock:
        read_status(sock)
        raw = recv_exact(sock, 188)

    return {
        "pid": struct.unpack_from("<I", raw, 0)[0],
        "name": raw[4:44].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
        "path": raw[44:108].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
        "titleid": raw[108:124].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
        "contentid": raw[124:188].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
    }


def get_process_maps(ip, pid):
    # Structure exacte du payload Pharaoh2k :
    # name[32] + start[8] + end[8] + offset[8] + prot[2]
    # Total = 58 octets.

    body = struct.pack("<I", pid)

    with send_command(
        ip, CMD_PROC_MAPS, body, timeout=20
    ) as sock:

        read_status(sock)
        count = struct.unpack("<I", recv_exact(sock, 4))[0]

        if count > 20000:
            raise ValueError(
                f"Nombre de mappings anormal: {count}"
            )

        raw = recv_exact(sock, count * 58)

    maps = []

    for i in range(count):
        entry = raw[i * 58:(i + 1) * 58]

        name = entry[:32].split(b"\\0", 1)[0].decode(
            "utf-8", errors="replace"
        )

        start, end, offset = struct.unpack_from(
            "<QQQ", entry, 32
        )

        prot = struct.unpack_from("<H", entry, 56)[0]

        maps.append({
            "start": hex(start),
            "end": hex(end),
            "offset": hex(offset),
            "protection": hex(prot),
            "name": name,
        })

    return maps


def get_foreground_app(ip):
    with send_command(
        ip, CMD_FOREGROUND_APP, timeout=8
    ) as sock:

        read_status(sock)
        raw = recv_exact(sock, 132)

    return {
        "pid": struct.unpack_from("<I", raw, 0)[0],
        "titleid": raw[4:20].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
        "contentid": raw[20:84].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
        "name": raw[84:124].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
        "app_ver": raw[124:132].split(b"\0", 1)[0].decode(
            "utf-8", errors="replace"
        ),
    }


def attempt(results, key, fn):
    try:
        value = fn()
        if isinstance(value, bytes):
            results[key] = {
                "hex": value.hex(),
                "text": value.decode("utf-8", errors="replace"),
            }
        else:
            results[key] = value

        print(f"[OK] {key}")

        return value

    except Exception as exc:
        results[key] = {"error": repr(exc)}

        print(f"[INFO] {key}: {exc}")

        return None


def main():

    ip = input(
        f"Adresse IP de la PS4 [{DEFAULT_IP}] : "
    ).strip() or DEFAULT_IP

    report = {
        "tool": "PS4 Linux Scout - read-only diagnostic",
        "date_utc": datetime.now(timezone.utc).isoformat(),
        "console_ip": ip,
        "port": PORT,
        "results": {},
    }

    r = report["results"]

    print(
        f"\n=== PS4 SCOUT - LECTURE SEULE ===\n"
        f"Cible: {ip}:{PORT}\n"
    )

    # Version du protocole

    raw = attempt(
        r,
        "protocol_version_raw",
        lambda: read_string_reply(ip, CMD_VERSION)
    )

    if raw is not None:
        r["protocol_version"] = raw.decode(
            "utf-8", errors="replace"
        )

    # Identité du payload

    raw = attempt(
        r,
        "branding_raw",
        lambda: read_string_reply(ip, CMD_BRANDING)
    )

    if raw is not None:
        brand, sep, capability = raw.partition(b"\0")

        r["payload_branding"] = brand.decode(
            "utf-8", errors="replace"
        )

        r["capability_level"] = (
            capability.decode("utf-8", errors="replace")
            if sep else None
        )

    # Firmware

    fw = attempt(
        r,
        "firmware_raw",
        lambda: read_u16_reply(ip, CMD_FW_VERSION)
    )

    if fw is not None:
        r["firmware_code"] = fw
        r["firmware"] = f"{fw // 100}.{fw % 100:02d}"

    # Plateforme

    attempt(
        r,
        "platform_id",
        lambda: read_u16_reply(ip, CMD_PLATFORM_ID)
    )

    # Base du noyau

    kbase = attempt(
        r,
        "kernel_base_int",
        lambda: get_kernel_base(ip)
    )

    if kbase is not None:

        r["kernel_base"] = hex(kbase)

        # Échantillon de 64 octets en lecture seule

        sample_hex = attempt(
            r,
            "kernel_base_sample_hex",
            lambda: read_kernel_bytes(ip, kbase, 64).hex()
        )

        if sample_hex is not None:

            sample = bytes.fromhex(sample_hex)

            r["kernel_base_sample_ascii"] = "".join(
                chr(b) if 32 <= b < 127 else "."
                for b in sample
            )

    # Processus

    procs = attempt(
        r,
        "processes",
        lambda: get_process_list(ip)
    )

    if procs is not None:

        print(
            f"Processus détectés: {len(procs)}"
        )

        selected_names = {
            "SceShellCore",
            "SceShellUI",
            "SceSystemService",
            "SceSpkService"
        }

        selected = [
            p for p in procs
            if p["name"] in selected_names
        ]

        r["selected_process_info"] = []
        r["selected_process_maps"] = {}

        for proc in selected:

            info = attempt(
                r,
                f"proc_info_{proc['name']}",
                lambda p=proc: get_process_info(
                    ip, p["pid"]
                )
            )

            if info is not None:
                r["selected_process_info"].append(info)

            maps = attempt(
                r,
                f"proc_maps_{proc['name']}",
                lambda p=proc: get_process_maps(
                    ip, p["pid"]
                )
            )

            if maps is not None:

                r["selected_process_maps"][
                    proc["name"]
                ] = maps

                print(
                    f"  {proc['name']} "
                    f"(PID {proc['pid']}): "
                    f"{len(maps)} mappings"
                )

    # Application au premier plan

    attempt(
        r,
        "foreground_app",
        lambda: get_foreground_app(ip)
    )

    # Sauvegarde JSON

    outdir = Path(
        "~/PS4/Linux/Scout/reports"
    ).expanduser()

    outdir.mkdir(
        parents=True,
        exist_ok=True
    )

    filename = datetime.now().strftime(
        "scout_readonly_%Y%m%d_%H%M%S.json"
    )

    output = outdir / filename

    output.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    print("\n=== FIN ===")

    print("Rapport JSON :", output)

    print(
        "Aucune écriture mémoire, modification de "
        "processus, attache debugger ou commande "
        "reboot n'a été envoyée."
    )


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\nInterrompu.")

    except Exception as exc:
        print("\nÉCHEC GLOBAL:", repr(exc))


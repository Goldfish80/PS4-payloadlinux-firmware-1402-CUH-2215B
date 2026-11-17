#!/usr/bin/env python3

import socket
import struct
import json
from pathlib import Path
from datetime import datetime

IP = "192.0.2.10"
PORT = 744
MAGIC = 0xFFAABBCC

CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
SUCCESS = 0x80000000

READ_SIZE = 4096


def receive(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connexion interrompue")

        data.extend(chunk)

    return bytes(data)


def request(sock, command, body=b""):
    sock.sendall(
        struct.pack(
            "<III",
            MAGIC,
            command,
            len(body)
        ) + body
    )


def check_status(sock):
    status = struct.unpack("<I", receive(sock, 4))[0]

    if status != SUCCESS:
        raise RuntimeError(
            f"Erreur PS4 : 0x{status:08X}"
        )


def main():

    print("=== PS4 KERNEL ELF PROBE ===")
    print(f"Connexion : {IP}:{PORT}")

    with socket.create_connection(
        (IP, PORT), timeout=8
    ) as sock:

        sock.settimeout(15)

        # Récupérer la base du noyau
        request(sock, CMD_KERN_BASE)
        check_status(sock)

        base = struct.unpack(
            "<Q", receive(sock, 8)
        )[0]

        print(f"\nKernel base : {base:#018x}")

        # Lecture en mémoire du noyau
        body = struct.pack(
            "<QI",
            base,
            READ_SIZE
        )

        request(sock, CMD_KERN_READ, body)
        check_status(sock)

        raw = receive(sock, READ_SIZE)

    print("[OK] 4096 octets récupérés.")

    # Sauvegarder le dump localement
    output_dir = Path(
        "~/PS4/Linux/Scout/reports"
    ).expanduser()

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    dump_path = output_dir / f"kernel_{stamp}.bin"

    dump_path.write_bytes(raw)

    # Décoder ELF64
    header = struct.unpack_from(
        "<16sHHIQQQIHHHHHH",
        raw,
        0
    )

    (
        ident,
        elf_type,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx
    ) = header

    if ident[:4] != b"\x7fELF":
        raise ValueError("Signature ELF invalide")

    if ident[4] != 2 or ident[5] != 1:
        raise ValueError("Format ELF inattendu")

    if phentsize != 56:
        raise ValueError(
            f"Taille des segments inattendue : {phentsize}"
        )

    if phnum > 64 or phoff + phnum * phentsize > len(raw):
        raise ValueError(
            "Table des segments hors de la zone lue"
        )

    print("\n========== ELF HEADER ==========")

    print("Type          :", elf_type)
    print("Machine       :", machine)
    print("Entry         :", hex(entry))
    print("Entry - base  :", hex(entry - base))
    print("PHDR offset   :", hex(phoff))
    print("PHDR size     :", phentsize)
    print("PHDR count    :", phnum)
    print("Section count :", shnum)

    types = {
        0: "NULL",
        1: "LOAD",
        2: "DYNAMIC",
        3: "INTERP",
        4: "NOTE",
        5: "SHLIB",
        6: "PHDR",
        7: "TLS"
    }

    segments = []

    print("\n========== ELF SEGMENTS ==========")

    for i in range(phnum):

        off = phoff + i * phentsize

        values = struct.unpack_from(
            "<IIQQQQQQ",
            raw,
            off
        )

        (
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align
        ) = values

        flags_text = "".join([
            "R" if p_flags & 4 else "-",
            "W" if p_flags & 2 else "-",
            "X" if p_flags & 1 else "-"
        ])

        segment = {
            "index": i,
            "type": types.get(p_type, hex(p_type)),
            "flags": flags_text,
            "offset": hex(p_offset),
            "vaddr": hex(p_vaddr),
            "paddr": hex(p_paddr),
            "filesz": hex(p_filesz),
            "memsz": hex(p_memsz),
            "align": hex(p_align)
        }

        segments.append(segment)

        print(f"\nSegment {i} : {segment['type']}")
        print("  Flags :", flags_text)
        print("  Offset:", hex(p_offset))
        print("  Vaddr :", hex(p_vaddr))
        print("  Paddr :", hex(p_paddr))
        print("  File  :", hex(p_filesz))
        print("  Memory:", hex(p_memsz))
        print("  Align :", hex(p_align))

    report = {
        "kernel_base": hex(base),
        "entry": hex(entry),
        "elf_type": elf_type,
        "machine": machine,
        "phnum": phnum,
        "segments": segments,
        "dump": str(dump_path)
    }

    report_path = output_dir / f"kernel_{stamp}.json"

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n========== TERMINÉ ==========")
    print("Dump :", dump_path)
    print("JSON :", report_path)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("\nÉCHEC :", repr(error))

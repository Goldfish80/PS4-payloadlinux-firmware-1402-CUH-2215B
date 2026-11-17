import os
import socket
import struct
import hashlib
from pathlib import Path

IP = "192.0.2.10"
PORT = 744

MAGIC = 0xFFAABBCC
CMD_KERN_READ = 0xBDCC0002
CMD_SUCCESS = 0x80000000

CHUNK_SIZE = 0x10000

SEGMENTS = [
    {
        "name": "TEXT",
        "address": 0xffffffffc7114000,
        "file_offset": 0x000000,
        "size": 0xcfe9a0,
    },
    {
        "name": "RELRO",
        "address": 0xffffffffc8213000,
        "file_offset": 0xcff000,
        "size": 0x020cc0,
    },
    {
        "name": "DATA",
        "address": 0xffffffffc8634000,
        "file_offset": 0xd20000,
        "size": 0x606690,
    },
]

OUTPUT = Path.home() / "PS4/Linux/Scout/reports/kernel_20261115_full.elf"


def recv_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        block = sock.recv(length - len(data))

        if not block:
            raise ConnectionError("Connexion fermée pendant la lecture")

        data.extend(block)

    return bytes(data)


def kernel_read(sock, address, length):
    header = struct.pack(
        "<III",
        MAGIC,
        CMD_KERN_READ,
        12
    )

    body = struct.pack(
        "<QI",
        address,
        length
    )

    sock.sendall(header + body)

    status = struct.unpack("<I", recv_exact(sock, 4))[0]

    if status != CMD_SUCCESS:
        raise RuntimeError(
            f"KERN_READ refusé : status={status:#010x}, "
            f"adresse={address:#018x}, longueur={length:#x}"
        )

    return recv_exact(sock, length)


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    total_size = max(
        s["file_offset"] + s["size"]
        for s in SEGMENTS
    )

    print("========== PS4 KERNEL DUMP ==========")
    print(f"Console : {IP}:{PORT}")
    print(f"Taille ELF prévue : {total_size:#x} ({total_size / 1024 / 1024:.2f} MiB)")
    print(f"Sortie : {OUTPUT}")
    print()

    with socket.create_connection((IP, PORT), timeout=15) as sock:
        sock.settimeout(30)

        with open(OUTPUT, "wb") as output:
            output.truncate(total_size)

            for segment in SEGMENTS:
                name = segment["name"]
                address = segment["address"]
                file_offset = segment["file_offset"]
                size = segment["size"]

                print(f"\n[{name}]")
                print(f"Adresse mémoire : {address:#018x}")
                print(f"Offset ELF      : {file_offset:#x}")
                print(f"Taille          : {size:#x}")

                position = 0

                while position < size:
                    amount = min(CHUNK_SIZE, size - position)

                    data = kernel_read(
                        sock,
                        address + position,
                        amount
                    )

                    output.seek(file_offset + position)
                    output.write(data)

                    position += amount

                    if position == size or position % 0x100000 < CHUNK_SIZE:
                        percent = position * 100 / size
                        print(
                            f"\rProgression : {percent:6.2f}% "
                            f"({position:#x}/{size:#x})",
                            end="",
                            flush=True
                        )

                print("\nSegment terminé.")

    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()

    print("\n========== TERMINÉ ==========")
    print(f"Fichier : {OUTPUT}")
    print(f"Taille  : {OUTPUT.stat().st_size} octets")
    print(f"SHA256  : {digest}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"\nERREUR : {error}")
        raise

#!/usr/bin/env python3

import os
import csv
import json
import re
import socket
import struct
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter

# ============================================================
# PS4 KERNEL SYMBOL ANALYZER
# Firmware utilisateur : 14.02
# Lecture seule : aucune écriture sur la PS4
# ============================================================

HOME = Path.home()
ROOT = HOME / "PS4/Linux/Scout"
REPORTS = ROOT / "reports"

ELF = REPORTS / "kernel_20261115_full.elf"

IP = os.environ.get("PS4_IP", "192.0.2.10")
PORT = int(os.environ.get("PS4_PORT", "744"))

PREFERRED_BASE = 0xFFFFFFFF82200000

MAGIC = 0xFFAABBCC
SUCCESS = 0x80000000

CMD_FW_VERSION = 0xBD000500
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002

PT_LOAD = 1
PT_DYNAMIC = 2
PT_SCE_RELRO = 0x61000010

DT_SCE_HASH = 0x61000025
DT_SCE_RELA = 0x6100002F
DT_SCE_RELASZ = 0x61000031
DT_SCE_RELAENT = 0x61000033
DT_SCE_STRTAB = 0x61000035
DT_SCE_STRSZ = 0x61000037
DT_SCE_SYMTAB = 0x61000039
DT_SCE_SYMENT = 0x6100003B
DT_SCE_HASHSZ = 0x6100003D
DT_SCE_SYMTABSZ = 0x6100003F

DT_INIT = 12

TAGS = {
    0x61000009: "DT_SCE_ORIGINAL_FILENAME",
    0x6100000D: "DT_SCE_MODULE_INFO",
    0x61000011: "DT_SCE_MODULE_ATTR",
    DT_SCE_HASH: "DT_SCE_HASH",
    0x61000027: "DT_SCE_PLTGOT",
    0x61000029: "DT_SCE_JMPREL",
    0x6100002B: "DT_SCE_PLTREL",
    0x6100002D: "DT_SCE_PLTRELSZ",
    DT_SCE_RELA: "DT_SCE_RELA",
    DT_SCE_RELASZ: "DT_SCE_RELASZ",
    DT_SCE_RELAENT: "DT_SCE_RELAENT",
    DT_SCE_STRTAB: "DT_SCE_STRTAB",
    DT_SCE_STRSZ: "DT_SCE_STRSZ",
    DT_SCE_SYMTAB: "DT_SCE_SYMTAB",
    DT_SCE_SYMENT: "DT_SCE_SYMENT",
    DT_SCE_HASHSZ: "DT_SCE_HASHSZ",
    DT_SCE_SYMTABSZ: "DT_SCE_SYMTABSZ",
    DT_INIT: "DT_INIT",
    21: "DT_DEBUG",
    30: "DT_FLAGS",
    0: "DT_NULL"
}

RELOC_TYPES = {
    0: "R_X86_64_NONE",
    1: "R_X86_64_64",
    2: "R_X86_64_PC32",
    3: "R_X86_64_GOT32",
    4: "R_X86_64_PLT32",
    5: "R_X86_64_COPY",
    6: "R_X86_64_GLOB_DAT",
    7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE",
    9: "R_X86_64_GOTPCREL",
    10: "R_X86_64_32",
    11: "R_X86_64_32S",
    12: "R_X86_64_16",
    13: "R_X86_64_PC16",
    14: "R_X86_64_8",
    15: "R_X86_64_PC8",
    16: "R_X86_64_DTPMOD64",
    17: "R_X86_64_DTPOFF64",
    18: "R_X86_64_TPOFF64",
    24: "R_X86_64_PC64",
    25: "R_X86_64_GOTOFF64",
    26: "R_X86_64_GOTPC32",
    32: "R_X86_64_SIZE32",
    33: "R_X86_64_SIZE64",
    37: "R_X86_64_IRELATIVE"
}

# Fonctions et variables qui nous intéressent pour Linux/kexec.
NEEDLES = [
    "copyin", "copyout", "copyinstr", "copystr",
    "kernel_map", "kmem_alloc", "kmem_free", "kva_alloc",
    "pmap", "vtophys", "vm_page", "vm_phys", "vm_map",
    "sysent", "syscall", "syscallnames",
    "printf", "vprintf", "kprintf", "log",
    "smp_rendezvous", "sched_pin", "sched_unpin",
    "cpu_switch", "cpu_throw", "cpu_reset",
    "bcopy", "memcpy", "memmove", "bzero", "memset",
    "malloc", "free", "allproc", "proc0", "thread0",
    "curthread", "phys_avail", "vm_page_array",
    "msgbuf", "kernbase", "dmapbase", "dmaplimit",
    "kernel_vm_end", "kern_reboot", "elf64",
    "bus_space", "acpi", "pci", "apic", "lapic",
    "intr", "sflash", "belize", "radeon", "amd",
    "init_main", "root_mount", "mountroot",
    "kern_dynlib", "copyoutstr", "copyinstr",
    "pmap_extract", "pmap_protect", "kmem_alloc_contig"
]

OUT = REPORTS / (
    "symbols_" + datetime.now().strftime("%Y%m%d_%H%M%S")
)
OUT.mkdir(parents=True, exist_ok=True)

LOG = []


def say(value=""):
    value = str(value)
    print(value)
    LOG.append(value)


def section(name):
    say("\n" + "=" * 15 + " " + name + " " + "=" * 15)


def hx(value):
    return hex(value) if value is not None else ""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_tsv(path, rows, columns):

    with open(path, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=columns,
            delimiter="\t",
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# 1. LECTURE ELF
# ============================================================

def parse_elf():

    if not ELF.exists():
        raise FileNotFoundError(f"ELF introuvable : {ELF}")

    data = ELF.read_bytes()

    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("Signature ELF invalide.")

    h = struct.unpack_from(
        "<16sHHIQQQIHHHHHH",
        data,
        0
    )

    (
        ident, etype, machine, version, entry,
        phoff, shoff, flags, ehsize,
        phentsize, phnum, shentsize, shnum, shstrndx
    ) = h

    if ident[4] != 2 or ident[5] != 1 or machine != 62:
        raise ValueError("ELF64 little-endian x86-64 attendu.")

    if phentsize < 56 or phnum > 256:
        raise ValueError("Program headers invalides.")

    if phoff + phentsize * phnum > len(data):
        raise ValueError("Program headers hors fichier.")

    segments = []

    for i in range(phnum):

        values = struct.unpack_from(
            "<IIQQQQQQ",
            data,
            phoff + i * phentsize
        )

        (
            p_type, p_flags, p_offset, p_vaddr,
            p_paddr, p_filesz, p_memsz, p_align
        ) = values

        if p_offset + p_filesz > len(data):
            raise ValueError(
                f"Segment {i}: données hors fichier."
            )

        segments.append({
            "index": i,
            "type": p_type,
            "flags": p_flags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "paddr": p_paddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align
        })

    loads = [
        x for x in segments
        if x["type"] == PT_LOAD
    ]

    if not loads:
        raise ValueError("Aucun PT_LOAD.")

    runtime_base = min(x["vaddr"] for x in loads)

    return {
        "data": data,
        "header": {
            "type": etype,
            "machine": machine,
            "entry": entry,
            "phoff": phoff,
            "phnum": phnum,
            "shoff": shoff,
            "shnum": shnum,
            "osabi": ident[7]
        },
        "segments": segments,
        "runtime_base": runtime_base,
        "slide": runtime_base - PREFERRED_BASE
    }


# ============================================================
# 2. ADRESSES - LINK / RUNTIME / FICHIER
# ============================================================

def map_runtime(e, address, length=1):

    for p in e["segments"]:

        start = p["vaddr"]
        file_end = start + p["filesz"]
        mem_end = start + p["memsz"]

        if start <= address and address + length <= mem_end:

            in_file = address + length <= file_end

            file_offset = None

            if in_file:
                file_offset = (
                    p["offset"] + address - start
                )

            name = {
                PT_LOAD: (
                    "LOAD_X"
                    if p["flags"] & 1
                    else "LOAD_DATA"
                ),
                PT_SCE_RELRO: "SCE_RELRO"
            }.get(p["type"], f"TYPE_{p['type']:X}")

            return {
                "segment": name,
                "file_offset": file_offset,
                "file_backed": in_file,
                "memory_start": start,
                "memory_end": mem_end,
                "file_end": file_end,
                "available_file": max(0, file_end - address),
                "available_memory": max(0, mem_end - address)
            }

    return None


def link_pointer_to_file(e, link_address, length=1):

    runtime_address = link_address + e["slide"]

    mapped = map_runtime(
        e,
        runtime_address,
        length
    )

    if not mapped or not mapped["file_backed"]:
        return None

    return mapped["file_offset"]


# ============================================================
# 3. PT_DYNAMIC
# ============================================================

def parse_dynamic(e):

    dyn_segment = next(
        (
            p for p in e["segments"]
            if p["type"] == PT_DYNAMIC
        ),
        None
    )

    if dyn_segment is None:
        raise ValueError("PT_DYNAMIC absent.")

    data = e["data"]
    off = dyn_segment["offset"]
    size = dyn_segment["filesz"]

    tags = {}
    entries = []

    for pos in range(0, size - 15, 16):

        tag, value = struct.unpack_from(
            "<qQ",
            data,
            off + pos
        )

        entries.append((tag, value))

        if tag == 0:
            break

        tags[tag] = value

    return dyn_segment, tags, entries


# ============================================================
# 4. TABLE DES CHAINES ET DES SYMBOLES SONY
# ============================================================

def decode_symbols(e, dyn):

    required = [
        DT_SCE_STRTAB,
        DT_SCE_STRSZ,
        DT_SCE_SYMTAB,
        DT_SCE_SYMENT,
        DT_SCE_SYMTABSZ
    ]

    missing = [x for x in required if x not in dyn]

    if missing:
        raise ValueError(
            "Tags dynamiques manquants : "
            + ", ".join(hex(x) for x in missing)
        )

    str_link = dyn[DT_SCE_STRTAB]
    str_size = dyn[DT_SCE_STRSZ]

    sym_link = dyn[DT_SCE_SYMTAB]
    sym_size = dyn[DT_SCE_SYMTABSZ]
    sym_entry = dyn[DT_SCE_SYMENT]

    if sym_entry != 24:
        raise ValueError(
            f"SYMENT inattendu: {sym_entry:#x}"
        )

    if sym_size % sym_entry:
        raise ValueError(
            "SYMTABSZ n'est pas divisible par SYMENT."
        )

    str_off = link_pointer_to_file(
        e,
        str_link,
        str_size
    )

    sym_off = link_pointer_to_file(
        e,
        sym_link,
        sym_size
    )

    if str_off is None or sym_off is None:
        raise ValueError(
            "Impossible de localiser les tables. "
            "Vérifier la base préférée et le slide."
        )

    data = e["data"]

    str_data = data[str_off:str_off + str_size]

    if len(str_data) != str_size:
        raise ValueError("Table des chaînes tronquée.")

    count = sym_size // sym_entry

    symbols = []

    for i in range(count):

        pos = sym_off + i * sym_entry

        (
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size
        ) = struct.unpack_from(
            "<IBBHQQ",
            data,
            pos
        )

        name = ""

        if st_name < str_size:

            end = str_data.find(b"\0", st_name)

            if end >= 0:

                name = str_data[
                    st_name:end
                ].decode(
                    "utf-8",
                    errors="replace"
                )

        st_bind = st_info >> 4
        st_type = st_info & 0x0F

        type_name = {
            0: "NOTYPE",
            1: "OBJECT",
            2: "FUNC",
            3: "SECTION",
            4: "FILE",
            5: "COMMON",
            6: "TLS"
        }.get(st_type, f"TYPE_{st_type}")

        bind_name = {
            0: "LOCAL",
            1: "GLOBAL",
            2: "WEAK"
        }.get(st_bind, f"BIND_{st_bind}")

        runtime_value = None
        rva = None
        mapped = None

        if st_value >= PREFERRED_BASE:

            rva = st_value - PREFERRED_BASE
            runtime_value = st_value + e["slide"]

            mapped = map_runtime(
                e,
                runtime_value,
                1
            )

        symbols.append({
            "index": i,
            "name": name,
            "name_index": st_name,
            "bind": bind_name,
            "type": type_name,
            "type_id": st_type,
            "other": st_other,
            "visibility": st_other & 3,
            "shndx": st_shndx,
            "link_value": st_value,
            "rva": rva,
            "runtime_value": runtime_value,
            "size": st_size,
            "segment": mapped["segment"] if mapped else "",
            "file_offset": (
                mapped["file_offset"] if mapped else None
            ),
            "file_backed": (
                mapped["file_backed"] if mapped else False
            ),
            "available_memory": (
                mapped["available_memory"] if mapped else 0
            ),
            "available_file": (
                mapped["available_file"] if mapped else 0
            )
        })

    return {
        "str_off": str_off,
        "str_size": str_size,
        "sym_off": sym_off,
        "sym_size": sym_size,
        "sym_entry": sym_entry,
        "count": count,
        "symbols": symbols
    }


# ============================================================
# 5. HASH SONY
# ============================================================

def decode_hash(e, dyn):

    if DT_SCE_HASH not in dyn or DT_SCE_HASHSZ not in dyn:
        return [], None

    link = dyn[DT_SCE_HASH]
    size = dyn[DT_SCE_HASHSZ]

    if size % 8:
        raise ValueError("HASHSZ non divisible par 8.")

    offset = link_pointer_to_file(e, link, size)

    if offset is None:
        raise ValueError("Table HASH non localisable.")

    rows = []
    data = e["data"]

    for i in range(size // 8):

        a, b, c, d = struct.unpack_from(
            "<HHHH",
            data,
            offset + i * 8
        )

        rows.append({
            "index": i,
            "bucket": a,
            "chain": b,
            "buckets": c,
            "chains": d
        })

    return rows, offset


# ============================================================
# 6. RELOCATIONS SCE
# ============================================================

def decode_relocations(e, dyn, symbols):

    required = [
        DT_SCE_RELA,
        DT_SCE_RELASZ,
        DT_SCE_RELAENT
    ]

    if not all(k in dyn for k in required):
        return [], None

    link = dyn[DT_SCE_RELA]
    size = dyn[DT_SCE_RELASZ]
    entry = dyn[DT_SCE_RELAENT]

    if entry != 24 or size % entry:
        raise ValueError(
            f"RELAENT/RELASZ inattendus: {entry:#x}/{size:#x}"
        )

    offset = link_pointer_to_file(e, link, size)

    if offset is None:
        raise ValueError("Table RELA non localisable.")

    rows = []
    data = e["data"]

    for i in range(size // entry):

        pos = offset + i * entry

        r_offset, r_info, r_addend = struct.unpack_from(
            "<QQq",
            data,
            pos
        )

        r_sym = r_info >> 32
        r_type = r_info & 0xFFFFFFFF

        sym_name = ""

        if r_sym < len(symbols):
            sym_name = symbols[r_sym]["name"]

        runtime_target = (
            r_offset + e["slide"]
            if r_offset >= PREFERRED_BASE
            else r_offset
        )

        target_map = map_runtime(
            e,
            runtime_target,
            1
        )

        if r_addend >= PREFERRED_BASE:
            runtime_addend = r_addend + e["slide"]
        else:
            runtime_addend = r_addend

        rows.append({
            "index": i,
            "offset_link": hx(r_offset),
            "offset_runtime": hx(runtime_target),
            "info": hx(r_info),
            "symbol_index": r_sym,
            "symbol": sym_name,
            "type_id": r_type,
            "type": RELOC_TYPES.get(
                r_type,
                f"UNKNOWN_{r_type:#x}"
            ),
            "addend_link": hx(r_addend),
            "addend_runtime": hx(runtime_addend),
            "target_segment": (
                target_map["segment"] if target_map else ""
            ),
            "target_file_offset": (
                hx(target_map["file_offset"])
                if target_map and target_map["file_offset"] is not None
                else ""
            )
        })

    return rows, offset


# ============================================================
# 7. RECHERCHE DES FONCTIONS / VARIABLES UTILES
# ============================================================

def is_candidate(name):

    low = name.lower()

    return any(
        needle.lower() in low
        for needle in NEEDLES
    )


def priority(name):

    low = name.lower()

    priorities = [
        "copyin", "copyout", "copyinstr",
        "kernel_map",
        "kmem_alloc", "kmem_free",
        "pmap", "vtophys",
        "vm_page", "vm_phys", "vm_map",
        "sysent", "syscall",
        "printf", "vprintf",
        "smp_rendezvous",
        "sched_pin", "sched_unpin",
        "cpu_switch", "cpu_throw",
        "kern_reboot",
        "phys_avail",
        "allproc", "proc0",
        "malloc", "free",
        "bcopy", "memcpy"
    ]

    for i, token in enumerate(priorities):

        if token in low:
            return i

    return len(priorities)


# ============================================================
# 8. LECTURE RESEAU PUREMENT LECTURE
# ============================================================

def recv_exact(sock, amount):

    result = bytearray()

    while len(result) < amount:

        part = sock.recv(amount - len(result))

        if not part:
            raise ConnectionError("Connexion interrompue.")

        result.extend(part)

    return bytes(result)


def send_command(sock, command, body=b""):

    sock.sendall(
        struct.pack(
            "<III",
            MAGIC,
            command,
            len(body)
        ) + body
    )


def read_status(sock):

    status = struct.unpack(
        "<I",
        recv_exact(sock, 4)
    )[0]

    if status != SUCCESS:
        raise RuntimeError(
            f"PS4 status: {status:#010x}"
        )


def kernel_read(sock, address, length):

    if length <= 0 or length > 0x1000:
        raise ValueError("Taille de lecture non autorisée.")

    send_command(
        sock,
        CMD_KERN_READ,
        struct.pack("<QI", address, length)
    )

    read_status(sock)

    return recv_exact(sock, length)


def live_validation(e, symbols, candidates):

    result = {
        "connected": False,
        "functions": [],
        "objects": []
    }

    say("\nLecture live : connexion à la PS4...")

    try:

        with socket.create_connection(
            (IP, PORT),
            timeout=10
        ) as sock:

            sock.settimeout(12)

            result["connected"] = True

            # Firmware : uint16, valeur numérique.
            send_command(sock, CMD_FW_VERSION)

            fw = struct.unpack(
                "<H",
                recv_exact(sock, 2)
            )[0]

            result["firmware_raw"] = fw
            result["firmware_hex"] = hex(fw)

            say(f"Firmware brut : {fw} ({hex(fw)})")

            if fw == 1402:
                say("Correspond à la valeur numérique 1402 du firmware 14.02.")

            # Base actuelle du noyau.
            send_command(sock, CMD_KERN_BASE)
            read_status(sock)

            live_base = struct.unpack(
                "<Q",
                recv_exact(sock, 8)
            )[0]

            live_slide = live_base - PREFERRED_BASE

            result["kernel_base"] = hx(live_base)
            result["slide"] = hx(live_slide)

            say(f"Base live : {live_base:#018x}")
            say(f"Slide live : {live_slide:#x}")

            # Fonctions : maximum 30 tests.
            function_targets = [
                x for x in candidates
                if (
                    x["type_id"] == 2
                    and x["shndx"] != 0
                    and x["file_offset"] is not None
                    and x["segment"] == "LOAD_X"
                )
            ]

            function_targets.sort(
                key=lambda x: (
                    priority(x["name"]),
                    x["rva"]
                )
            )

            seen = set()

            for sym in function_targets:

                if len(result["functions"]) >= 30:
                    break

                rva = sym["rva"]

                if rva in seen:
                    continue

                seen.add(rva)

                live_address = live_base + rva

                n = min(
                    16,
                    sym["available_file"],
                    sym["size"] if sym["size"] > 0 else 16
                )

                if n <= 0:
                    continue

                expected = e["data"][
                    sym["file_offset"]:sym["file_offset"] + n
                ]

                item = {
                    "name": sym["name"],
                    "offset": hx(rva),
                    "live_address": hx(live_address),
                    "length": n
                }

                try:

                    observed = kernel_read(
                        sock,
                        live_address,
                        n
                    )

                    item["live_bytes"] = observed.hex()
                    item["dump_bytes"] = expected.hex()
                    item["match"] = observed == expected

                except Exception as exc:

                    item["error"] = repr(exc)

                result["functions"].append(item)

            # Objets globaux : lecture courte (16 octets maximum).
            object_targets = [
                x for x in candidates
                if (
                    x["type_id"] == 1
                    and x["shndx"] != 0
                    and x["rva"] is not None
                )
            ]

            object_targets.sort(
                key=lambda x: (
                    priority(x["name"]),
                    x["rva"]
                )
            )

            seen = set()

            for sym in object_targets:

                if len(result["objects"]) >= 20:
                    break

                if sym["rva"] in seen:
                    continue

                seen.add(sym["rva"])

                n = min(
                    16,
                    sym["size"] if sym["size"] > 0 else 16,
                    sym["available_memory"]
                )

                if n <= 0:
                    continue

                live_address = live_base + sym["rva"]

                item = {
                    "name": sym["name"],
                    "offset": hx(sym["rva"]),
                    "live_address": hx(live_address),
                    "length": n,
                    "segment": sym["segment"],
                    "file_backed": sym["file_backed"]
                }

                try:

                    observed = kernel_read(
                        sock,
                        live_address,
                        n
                    )

                    item["live_bytes"] = observed.hex()

                    if sym["file_offset"] is not None:

                        expected = e["data"][
                            sym["file_offset"]:
                            sym["file_offset"] + n
                        ]

                        item["dump_bytes"] = expected.hex()
                        item["match"] = observed == expected

                except Exception as exc:

                    item["error"] = repr(exc)

                result["objects"].append(item)

        return result

    except Exception as exc:

        result["error"] = repr(exc)
        say(f"Lecture live indisponible : {exc!r}")

        return result


# ============================================================
# 9. PROGRAMME PRINCIPAL
# ============================================================

def main():

    section("IDENTIFICATION")

    say("Console cible : PS4 Slim CUH-2215B")
    say("Firmware déclaré : 14.02")
    say(f"IP : {IP}:{PORT}")
    say(f"ELF : {ELF}")
    say(f"Sortie : {OUT}")

    e = parse_elf()

    data = e["data"]
    base = e["runtime_base"]
    slide = e["slide"]

    say(f"Taille ELF : {len(data)}")
    say(f"SHA256 : {digest(data)}")

    if len(data) != 20080272:
        say("AVERTISSEMENT : taille différente du dump précédent.")

    section("BASES ET SEGMENTS")

    say(f"Base préférée : {PREFERRED_BASE:#018x}")
    say(f"Base runtime du dump : {base:#018x}")
    say(f"Slide : {slide:#x}")
    say(f"Entry ELF : {e['header']['entry']:#018x}")
    say(
        f"Entry RVA : "
        f"{e['header']['entry'] - base:#x}"
    )

    segment_rows = []

    for p in e["segments"]:

        name = {
            PT_LOAD: "PT_LOAD",
            PT_DYNAMIC: "PT_DYNAMIC",
            PT_SCE_RELRO: "PT_SCE_RELRO"
        }.get(p["type"], hex(p["type"]))

        link_vaddr = p["vaddr"] - slide

        missing = p["memsz"] - p["filesz"]

        row = {
            "index": p["index"],
            "type": name,
            "runtime": hx(p["vaddr"]),
            "link": hx(link_vaddr),
            "offset": hx(p["offset"]),
            "filesz": hx(p["filesz"]),
            "memsz": hx(p["memsz"]),
            "missing": hx(missing),
            "flags": hx(p["flags"])
        }

        segment_rows.append(row)

        say(
            f"{name:<14} "
            f"runtime={p['vaddr']:#018x} "
            f"link={link_vaddr:#018x} "
            f"off={p['offset']:#x} "
            f"file={p['filesz']:#x} "
            f"mem={p['memsz']:#x} "
            f"non-dump={missing:#x}"
        )

    # PT_DYNAMIC
    section("DYNAMIC TAGS")

    dyn_segment, dyn, dyn_entries = parse_dynamic(e)

    say(
        f"PT_DYNAMIC offset={dyn_segment['offset']:#x} "
        f"VA={dyn_segment['vaddr']:#018x}"
    )

    for tag, value in dyn_entries:

        say(
            f"{TAGS.get(tag, 'UNKNOWN'):25} "
            f"tag={tag:#x} "
            f"value={value:#018x}"
        )

    # Résolution des tables
    section("RESOLUTION DES TABLES SONY")

    pointer_tags = [
        (DT_SCE_STRTAB, "STRTAB", DT_SCE_STRSZ),
        (DT_SCE_SYMTAB, "SYMTAB", DT_SCE_SYMTABSZ),
        (DT_SCE_RELA, "RELA", DT_SCE_RELASZ),
        (DT_SCE_HASH, "HASH", DT_SCE_HASHSZ)
    ]

    resolved_tables = {}

    for tag, name, size_tag in pointer_tags:

        if tag not in dyn or size_tag not in dyn:
            say(f"{name}: information manquante.")
            continue

        link = dyn[tag]
        size = dyn[size_tag]

        runtime = link + slide

        offset = link_pointer_to_file(
            e,
            link,
            size
        )

        resolved_tables[name] = {
            "link_address": hx(link),
            "runtime_address": hx(runtime),
            "file_offset": hx(offset) if offset is not None else None,
            "size": hx(size)
        }

        say(
            f"{name:<8} "
            f"link={link:#018x} "
            f"runtime={runtime:#018x} "
            f"file_offset={hx(offset)} "
            f"size={size:#x}"
        )

    # INIT
    if DT_INIT in dyn:

        init = dyn[DT_INIT]

        say(
            f"DT_INIT : link={init:#018x} "
            f"RVA={init - PREFERRED_BASE:#x} "
            f"runtime={init + slide:#018x}"
        )

    # Symboles
    section("TABLE DES SYMBOLES")

    symbol_info = decode_symbols(e, dyn)
    symbols = symbol_info["symbols"]

    say(f"STR tab file offset : {symbol_info['str_off']:#x}")
    say(f"SYM tab file offset : {symbol_info['sym_off']:#x}")
    say(f"SYMENT : {symbol_info['sym_entry']}")
    say(f"SYMTABSZ : {symbol_info['sym_size']:#x}")
    say(f"Nombre d'entrées : {symbol_info['count']:,}")

    named = [
        s for s in symbols
        if s["name"]
    ]

    functions = [
        s for s in symbols
        if s["type_id"] == 2 and s["shndx"] != 0
    ]

    objects = [
        s for s in symbols
        if s["type_id"] == 1 and s["shndx"] != 0
    ]

    adjusted_mapped = sum(
        1 for s in symbols
        if s["runtime_value"] is not None
        and map_runtime(e, s["runtime_value"], 1)
    )

    raw_mapped = sum(
        1 for s in symbols
        if s["link_value"]
        and map_runtime(e, s["link_value"], 1)
    )

    say(f"Entrées nommées : {len(named)}")
    say(f"Fonctions définies : {len(functions)}")
    say(f"Objets définis : {len(objects)}")

    say(
        f"Adresses mappées après slide : {adjusted_mapped}"
    )

    say(
        f"Adresses mappées sans slide : {raw_mapped}"
    )

    all_symbol_rows = []

    for s in symbols:

        all_symbol_rows.append({
            "index": s["index"],
            "name": s["name"],
            "name_index": s["name_index"],
            "bind": s["bind"],
            "type": s["type"],
            "shndx": s["shndx"],
            "link_address": hx(s["link_value"]),
            "rva": hx(s["rva"]),
            "runtime_address": hx(s["runtime_value"]),
            "size": hx(s["size"]),
            "segment": s["segment"],
            "file_offset": hx(s["file_offset"]),
            "file_backed": s["file_backed"]
        })

    write_tsv(
        OUT / "symbols_all.tsv",
        all_symbol_rows,
        [
            "index", "name", "name_index", "bind",
            "type", "shndx", "link_address",
            "rva", "runtime_address", "size",
            "segment", "file_offset", "file_backed"
        ]
    )

    # Candidats Linux/kexec
    candidates = [
        s for s in symbols
        if s["name"] and is_candidate(s["name"])
    ]

    candidates.sort(
        key=lambda x: (
            priority(x["name"]),
            x["rva"] if x["rva"] is not None else 0
        )
    )

    candidate_rows = []

    for s in candidates:

        candidate_rows.append({
            "index": s["index"],
            "name": s["name"],
            "type": s["type"],
            "bind": s["bind"],
            "shndx": s["shndx"],
            "link_address": hx(s["link_value"]),
            "offset_from_preferred_base": hx(s["rva"]),
            "runtime_address": hx(s["runtime_value"]),
            "size": hx(s["size"]),
            "segment": s["segment"],
            "file_offset": hx(s["file_offset"]),
            "file_backed": s["file_backed"]
        })

    write_tsv(
        OUT / "symbols_candidates.tsv",
        candidate_rows,
        [
            "index", "name", "type", "bind", "shndx",
            "link_address", "offset_from_preferred_base",
            "runtime_address", "size", "segment",
            "file_offset", "file_backed"
        ]
    )

    say(
        f"\nCandidats trouvés : {len(candidates)}"
    )

    for s in candidates[:150]:

        say(
            f"{s['type']:<8} "
            f"{s['name']:<48} "
            f"RVA={hx(s['rva']):>12} "
            f"runtime={hx(s['runtime_value'])} "
            f"size={hx(s['size'])} "
            f"{s['segment']}"
        )

    # Hash
    section("HASH SONY")

    hash_rows, hash_off = decode_hash(e, dyn)

    if hash_rows:

        write_tsv(
            OUT / "sce_hash.tsv",
            hash_rows,
            ["index", "bucket", "chain", "buckets", "chains"]
        )

        nonzero = sum(
            1 for row in hash_rows
            if any(
                row[k]
                for k in ("bucket", "chain", "buckets", "chains")
            )
        )

        say(f"Offset fichier : {hash_off:#x}")
        say(f"Taille : {dyn[DT_SCE_HASHSZ]:#x}")
        say(f"Entrées de 8 octets : {len(hash_rows)}")
        say(f"Entrées non nulles : {nonzero}")

        say("Premières entrées :")

        for row in hash_rows[:20]:

            say(
                f"  {row['index']:5} "
                f"{row['bucket']:5} "
                f"{row['chain']:5} "
                f"{row['buckets']:5} "
                f"{row['chains']:5}"
            )

    else:

        say("Aucune table hash exploitable.")

    # Relocations
    section("RELOCATIONS")

    relocations, rela_off = decode_relocations(
        e,
        dyn,
        symbols
    )

    relocation_counts = Counter(
        row["type"]
        for row in relocations
    )

    if relocations:

        write_tsv(
            OUT / "relocations.tsv",
            relocations,
            [
                "index",
                "offset_link",
                "offset_runtime",
                "info",
                "symbol_index",
                "symbol",
                "type_id",
                "type",
                "addend_link",
                "addend_runtime",
                "target_segment",
                "target_file_offset"
            ]
        )

        say(f"Offset fichier : {rela_off:#x}")
        say(f"Nombre de relocations : {len(relocations):,}")

        say("Répartition des types :")

        for name, count in relocation_counts.most_common(30):
            say(f"  {name:<28} {count}")

        referenced = Counter(
            row["symbol"]
            for row in relocations
            if row["symbol"]
        )

        say("Symboles les plus référencés :")

        for name, count in referenced.most_common(40):
            say(f"  {name:<42} {count}")

    else:

        say("Aucune relocation exploitable.")

    # Vérification des limites internes
    section("VERIFICATION DES LIMITES DES TABLES")

    checks = {}

    if (
        "STRTAB" in resolved_tables
        and "SYMTAB" in resolved_tables
    ):

        a = int(
            resolved_tables["STRTAB"]["file_offset"],
            16
        )

        b = a + dyn[DT_SCE_STRSZ]

        c = int(
            resolved_tables["SYMTAB"]["file_offset"],
            16
        )

        checks["gap_STRtab_SYMtab"] = c - b

        say(
            f"Fin STRTAB : {b:#x} ; "
            f"début SYMTAB : {c:#x} ; "
            f"écart : {c-b:#x}"
        )

    if (
        "SYMTAB" in resolved_tables
        and "RELA" in resolved_tables
    ):

        a = int(
            resolved_tables["SYMTAB"]["file_offset"],
            16
        )

        b = a + dyn[DT_SCE_SYMTABSZ]

        c = int(
            resolved_tables["RELA"]["file_offset"],
            16
        )

        checks["gap_SYMtab_RELA"] = c - b

        say(
            f"Fin SYMTAB : {b:#x} ; "
            f"début RELA : {c:#x} ; "
            f"écart : {c-b:#x}"
        )

    if (
        "RELA" in resolved_tables
        and "HASH" in resolved_tables
    ):

        a = int(
            resolved_tables["RELA"]["file_offset"],
            16
        )

        b = a + dyn[DT_SCE_RELASZ]

        c = int(
            resolved_tables["HASH"]["file_offset"],
            16
        )

        checks["gap_RELA_HASH"] = c - b

        say(
            f"Fin RELA : {b:#x} ; "
            f"début HASH : {c:#x} ; "
            f"écart : {c-b:#x}"
        )

    if "HASH" in resolved_tables:

        a = int(
            resolved_tables["HASH"]["file_offset"],
            16
        )

        b = a + dyn[DT_SCE_HASHSZ]

        c = dyn_segment["offset"]

        checks["gap_HASH_DYNAMIC"] = c - b

        say(
            f"Fin HASH : {b:#x} ; "
            f"début DYNAMIC : {c:#x} ; "
            f"écart : {c-b:#x}"
        )

    # Live validation
    section("VALIDATION DES OFFSETS SUR LA PS4")

    live = live_validation(
        e,
        symbols,
        candidates
    )

    function_rows = live.get("functions", [])
    object_rows = live.get("objects", [])

    write_tsv(
        OUT / "live_validation.tsv",
        function_rows,
        [
            "name", "offset", "live_address", "length",
            "live_bytes", "dump_bytes", "match", "error"
        ]
    )

    write_tsv(
        OUT / "live_objects.tsv",
        object_rows,
        [
            "name", "offset", "live_address",
            "length", "segment", "file_backed",
            "live_bytes", "dump_bytes", "match", "error"
        ]
    )

    matched = sum(
        1 for row in function_rows
        if row.get("match") is True
    )

    say(
        f"Fonctions comparées : {len(function_rows)}"
    )

    say(
        f"Correspondances exactes : {matched}"
    )

    for row in function_rows:

        say(
            f"  {row['name']:<40} "
            f"RVA={row['offset']:<12} "
            f"match={row.get('match', 'ERREUR')}"
        )

    say(
        f"Objets globaux examinés : {len(object_rows)}"
    )

    # Résumé JSON
    section("SAUVEGARDE")

    summary = {
        "firmware_user": "14.02",
        "target": {
            "model": "CUH-2215B",
            "southbridge": "Belize2 A0",
            "ip": IP,
            "port": PORT
        },
        "elf": {
            "path": str(ELF),
            "size": len(data),
            "sha256": digest(data),
            "runtime_base": hx(base),
            "preferred_base": hx(PREFERRED_BASE),
            "slide": hx(slide),
            "entry": hx(e["header"]["entry"])
        },
        "segments": segment_rows,
        "dynamic_tables": resolved_tables,
        "table_checks": checks,
        "symbols": {
            "total_entries": len(symbols),
            "named": len(named),
            "functions": len(functions),
            "objects": len(objects),
            "candidates": len(candidates),
            "mapped_after_slide": adjusted_mapped,
            "mapped_without_slide": raw_mapped
        },
        "hash": {
            "entries": len(hash_rows),
            "file_offset": hx(hash_off) if hash_off is not None else None
        },
        "relocations": {
            "entries": len(relocations),
            "file_offset": hx(rela_off) if rela_off is not None else None,
            "types": dict(relocation_counts)
        },
        "live_validation": live
    }

    json_path = OUT / "summary.json"
    text_path = OUT / "summary.txt"

    json_path.write_text(
        json.dumps(
            summary,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

    text_path.write_text(
        "\n".join(LOG) + "\n",
        encoding="utf-8"
    )

    say(f"Rapport texte : {text_path}")
    say(f"Rapport JSON : {json_path}")
    say(f"Symboles complets : {OUT / 'symbols_all.tsv'}")
    say(f"Candidats : {OUT / 'symbols_candidates.tsv'}")
    say(f"Relocations : {OUT / 'relocations.tsv'}")
    say(f"Hash : {OUT / 'sce_hash.tsv'}")
    say(f"Validation live : {OUT / 'live_validation.tsv'}")
    say(f"Objets live : {OUT / 'live_objects.tsv'}")

    print("\nANALYSE TERMINEE.")


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\nInterruption demandée.")

    except Exception as exc:
        print(f"\nERREUR : {exc!r}")
        raise

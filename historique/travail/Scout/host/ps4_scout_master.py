#!/usr/bin/env python3

import os, sys, re, json, socket, struct, hashlib, subprocess
from pathlib import Path
from datetime import datetime
from collections import Counter

HOME = Path.home()
SCOUT = HOME / "PS4/Linux/Scout"
REPORTS = SCOUT / "reports"
ELF = REPORTS / "kernel_20261115_full.elf"
SMALL_DUMP = REPORTS / "kernel_20261115_192141.bin"
SCOUT_JSON = REPORTS / "scout_readonly_20261115_190922.json"
SOURCE = SCOUT / "upstream/ps4debug-NG"
PAYLOAD = SOURCE / "ps4debug-ng.bin"

IP = os.environ.get("PS4_IP", "192.0.2.10")
PORT = int(os.environ.get("PS4_PORT", "744"))

MAGIC = 0xFFAABBCC
SUCCESS = 0x80000000

CMD_VERSION = 0xBD000001
CMD_FW_VERSION = 0xBD000500
CMD_BRANDING = 0xBD000501
CMD_PROTOCOL_ID = 0xBD000502
CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_MAPS = 0xBDAA0004
CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002

STAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTDIR = REPORTS / f"master_{STAMP}"
OUTDIR.mkdir(parents=True, exist_ok=True)

LOG = []
RESULT = {
    "timestamp": STAMP,
    "ps4_ip": IP,
    "ps4_port": PORT,
    "read_only": True
}


def say(s=""):
    s = str(s)
    print(s)
    LOG.append(s)


def section(title):
    say("\n" + "=" * 18 + f" {title} " + "=" * 18)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run_cmd(args):
    try:
        p = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
            check=False
        )
        return p.stdout.strip()
    except Exception as e:
        return f"[indisponible: {e}]"


# ------------------------------------------------------------
# STRUCTURE REELLE DES CARTES MEMOIRE
# ------------------------------------------------------------

def locate_struct_header():

    candidates = [
        SOURCE / "kdebugger/include/proc.h",
        SOURCE / "installer/include/proc.h",
        SOURCE / "debugger/include/proc.h",
    ]

    for p in candidates:

        if not p.exists():
            continue

        t = p.read_text(errors="replace")

        m = re.search(
            r"struct\s+proc_vm_map_entry\s*\{(.*?)\}\s*([^;]{0,160})",
            t,
            re.S
        )

        if not m:
            continue

        body, tail = m.group(1), m.group(2)

        packed = (
            "packed" in tail
            or "packed" in t[m.start():m.end()]
        )

        fields = []

        field_re = re.compile(
            r"^\s*(char|uint8_t|uint16_t|uint32_t|uint64_t|"
            r"int8_t|int16_t|int32_t|int64_t|uintptr_t|size_t|"
            r"int|unsigned\s+int|long|unsigned\s+long)"
            r"\s+([A-Za-z_]\w*)"
            r"\s*(?:\[\s*(\d+)\s*\])?\s*;",
            re.M
        )

        sizes = {
            "char": 1,
            "uint8_t": 1,
            "int8_t": 1,
            "uint16_t": 2,
            "int16_t": 2,
            "uint32_t": 4,
            "int32_t": 4,
            "int": 4,
            "unsigned int": 4,
            "uint64_t": 8,
            "int64_t": 8,
            "uintptr_t": 8,
            "size_t": 8,
            "long": 8,
            "unsigned long": 8
        }

        offset = 0
        struct_align = 1

        for fm in field_re.finditer(body):

            typ, name, arr = fm.groups()

            sz = sizes[typ] * (int(arr) if arr else 1)
            align = 1 if typ == "char" else min(sizes[typ], 8)

            if not packed:
                offset = (offset + align - 1) // align * align

            fields.append({
                "name": name,
                "type": typ,
                "size": sz,
                "offset": offset
            })

            offset += sz
            struct_align = max(struct_align, align)

        total = (
            offset if packed
            else (offset + struct_align - 1) // struct_align * struct_align
        )

        field_names = {f["name"] for f in fields}

        if (
            fields
            and {"start", "end", "offset", "prot"}.issubset(field_names)
            and (field_names & {"name", "pathname", "path"})
        ):
            return {
                "path": str(p),
                "packed": packed,
                "fields": fields,
                "size": total,
                "source_text": m.group(0).strip()
            }

    return None


# ------------------------------------------------------------
# ANALYSE ELF64
# ------------------------------------------------------------

def parse_elf(path):

    data = path.read_bytes()

    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("Le fichier choisi n'est pas un ELF valide.")

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
        raise ValueError(
            "ELF inattendu: ELF64 little-endian x86-64 attendu."
        )

    if (
        phentsize < 56
        or phnum > 256
        or phoff + phnum * phentsize > len(data)
    ):
        raise ValueError("Table des program headers invalide.")

    phdrs = []

    for i in range(phnum):

        vals = struct.unpack_from(
            "<IIQQQQQQ",
            data,
            phoff + i * phentsize
        )

        (
            p_type, p_flags, p_offset, p_vaddr,
            p_paddr, p_filesz, p_memsz, p_align
        ) = vals

        bad = p_offset + p_filesz > len(data)

        phdrs.append({
            "index": i,
            "type": p_type,
            "flags": p_flags,
            "offset": p_offset,
            "vaddr": p_vaddr,
            "paddr": p_paddr,
            "filesz": p_filesz,
            "memsz": p_memsz,
            "align": p_align,
            "out_of_file": bad
        })

    loads = [p for p in phdrs if p["type"] == 1]

    if not loads:
        raise ValueError("Aucun segment PT_LOAD trouvé.")

    base = min(p["vaddr"] for p in loads)

    def va_to_off(va, size=1):

        for p in phdrs:

            if p["type"] in (1, 0x61000010) and p["filesz"]:

                lo = p["vaddr"]
                hi = p["vaddr"] + p["filesz"]

                if lo <= va and va + size <= hi:
                    return p["offset"] + (va - lo)

        if 0 <= va and va + size <= len(data):
            return va

        return None

    dyn = {}
    dyn_entries = []

    for p in phdrs:

        if p["type"] != 2 or p["out_of_file"]:
            continue

        n = min(p["filesz"] // 16, 4096)

        for j in range(n):

            tag, val = struct.unpack_from(
                "<qQ",
                data,
                p["offset"] + j * 16
            )

            dyn_entries.append((tag, val))

            if tag == 0:
                break

            dyn[tag] = val

        break

    return {
        "data": data,
        "header": {
            "type": etype,
            "machine": machine,
            "entry": entry,
            "phoff": phoff,
            "phentsize": phentsize,
            "phnum": phnum,
            "shoff": shoff,
            "shnum": shnum,
            "osabi": ident[7],
            "flags": flags,
            "ehsize": ehsize
        },
        "phdrs": phdrs,
        "base": base,
        "va_to_off": va_to_off,
        "dynamic": dyn,
        "dynamic_entries": dyn_entries
    }


# ------------------------------------------------------------
# TABLE DYNAMIQUE ET SYMBOLes
# ------------------------------------------------------------

def dynamic_symbol_analysis(e):

    data = e["data"]
    dyn = e["dynamic"]
    va_to_off = e["va_to_off"]

    names = {
        0: "DT_NULL",
        1: "DT_NEEDED",
        2: "DT_PLTRELSZ",
        3: "DT_PLTGOT",
        4: "DT_HASH",
        5: "DT_STRTAB",
        6: "DT_SYMTAB",
        7: "DT_RELA",
        8: "DT_RELASZ",
        9: "DT_RELAENT",
        10: "DT_STRSZ",
        11: "DT_SYMENT",
        12: "DT_INIT",
        13: "DT_FINI",
        14: "DT_SONAME",
        15: "DT_RPATH",
        16: "DT_SYMBOLIC",
        17: "DT_REL",
        18: "DT_RELSZ",
        19: "DT_RELENT",
        20: "DT_PLTREL",
        21: "DT_DEBUG",
        22: "DT_TEXTREL",
        23: "DT_JMPREL",
        24: "DT_BIND_NOW",
        25: "DT_INIT_ARRAY",
        26: "DT_FINI_ARRAY",
        27: "DT_INIT_ARRAYSZ",
        28: "DT_FINI_ARRAYSZ",
        29: "DT_RUNPATH",
        30: "DT_FLAGS",
        0x6ffffef5: "DT_GNU_HASH",
        0x61000025: "DT_SCE_HASH",
        0x61000035: "DT_SCE_STRTAB",
        0x61000037: "DT_SCE_STRSZ",
        0x61000039: "DT_SCE_SYMTAB",
        0x6100003b: "DT_SCE_SYMENT",
        0x6100003d: "DT_SCE_HASHSZ",
        0x6100003f: "DT_SCE_SYMTABSZ"
    }

    out = {
        "tags": [],
        "symbols_total": 0,
        "symbols_named": 0,
        "matches": []
    }

    for tag, val in e["dynamic_entries"]:
        out["tags"].append({
            "tag": hex(tag),
            "name": names.get(tag, "UNKNOWN"),
            "value": hex(val)
        })

    if not dyn:
        out["note"] = "Aucune entrée PT_DYNAMIC exploitable."
        return out

    symtab_va = dyn.get(6, dyn.get(0x61000039))
    strtab_va = dyn.get(5, dyn.get(0x61000035))
    strsz = dyn.get(10, dyn.get(0x61000037, 0))
    syment = dyn.get(11, dyn.get(0x6100003b, 24))

    if syment == 0 or syment > 256:
        syment = 24

    symoff = (
        va_to_off(symtab_va, syment)
        if symtab_va is not None else None
    )

    stroff = (
        va_to_off(strtab_va, max(1, min(strsz or 1, 16)))
        if strtab_va is not None else None
    )

    if symoff is None or stroff is None:
        out["note"] = (
            "DT_SYMTAB/DT_STRTAB absent ou pointeurs non mappables."
        )
        out["symtab_va"] = hex(symtab_va) if symtab_va is not None else None
        out["strtab_va"] = hex(strtab_va) if strtab_va is not None else None
        return out

    if not strsz or stroff + strsz > len(data):
        out["note"] = "DT_STRSZ absent ou table des chaînes hors fichier."
        return out

    count = None

    hash_va = dyn.get(4)

    if hash_va is not None:

        ho = va_to_off(hash_va, 8)

        if ho is not None:

            nbucket, nchain = struct.unpack_from("<II", data, ho)

            if (
                nchain < 2_000_000
                and ho + 8 + 4 * (nbucket + nchain) <= len(data)
            ):
                count = nchain
                out["hash"] = {
                    "type": "SYSV",
                    "nbucket": nbucket,
                    "nchain": nchain
                }

    if count is None and dyn.get(0x6ffffef5) is not None:

        gh = va_to_off(dyn[0x6ffffef5], 16)

        if gh is not None:

            nbuckets, symoffset, bloom_size, bloom_shift = (
                struct.unpack_from("<IIII", data, gh)
            )

            buckets_off = gh + 16 + bloom_size * 8
            chains_off = buckets_off + nbuckets * 4

            if (
                nbuckets < 1_000_000
                and bloom_size < 1_000_000
                and chains_off <= len(data)
            ):

                buckets = (
                    struct.unpack_from(
                        "<" + "I" * nbuckets,
                        data,
                        buckets_off
                    ) if nbuckets else ()
                )

                highest = 0
                valid = True

                for b in buckets:

                    if b == 0:
                        continue

                    if b < symoffset:
                        valid = False
                        break

                    idx = b

                    while True:

                        chain_off = chains_off + (idx - symoffset) * 4

                        if chain_off + 4 > len(data):
                            valid = False
                            break

                        word = struct.unpack_from(
                            "<I",
                            data,
                            chain_off
                        )[0]

                        highest = max(highest, idx)

                        if word & 1:
                            break

                        idx += 1

                    if not valid:
                        break

                if valid:
                    count = max(symoffset, highest + 1)
                    out["hash"] = {
                        "type": "GNU",
                        "nbuckets": nbuckets,
                        "symoffset": symoffset,
                        "bloom_size": bloom_size
                    }

    if count is None:

        sce_size = dyn.get(0x6100003f)

        if sce_size and sce_size % syment == 0:
            count = sce_size // syment
            out["hash"] = {
                "type": "SCE_SYMTABSZ",
                "size": hex(sce_size)
            }

    if count is None:
        out["note"] = (
            "DT_SYMTAB/DT_STRTAB présents, mais aucun compteur fiable "
            "(DT_HASH/GNU_HASH/SCE_SYMTABSZ)."
        )
        out["symtab_va"] = hex(symtab_va)
        out["strtab_va"] = hex(strtab_va)
        return out

    if count > 250_000 or symoff + count * syment > len(data):
        out["note"] = f"Table de symboles hors fichier ou démesurée: {count}."
        return out

    wanted = (
        "copyin", "copyout", "kernel_map", "kmem_alloc",
        "kmem_free", "pmap", "sysent", "printf",
        "smp_rendezvous", "vm_page", "phys_avail",
        "cpu_switch", "cpu_throw", "bcopy", "memcpy",
        "malloc", "free", "allproc", "proc0",
        "kernbase", "kernelbase"
    )

    symbols = []

    for i in range(count):

        off = symoff + i * syment

        if off + 24 > len(data):
            break

        (
            st_name, st_info, st_other,
            st_shndx, st_value, st_size
        ) = struct.unpack_from("<IBBHQQ", data, off)

        if st_name >= strsz:
            continue

        end = data.find(
            b"\0",
            stroff + st_name,
            stroff + strsz
        )

        if end < 0:
            continue

        name = data[stroff + st_name:end].decode(
            "utf-8", "replace"
        )

        if not name:
            continue

        out["symbols_named"] += 1

        if any(k in name.lower() for k in wanted):

            symbols.append({
                "name": name,
                "value": hex(st_value),
                "size": hex(st_size),
                "bind": st_info >> 4,
                "type": st_info & 15,
                "shndx": st_shndx,
                "rva_from_kernel_base": (
                    hex(st_value - e["base"])
                    if st_value >= e["base"] else None
                )
            })

    out["symbols_total"] = count
    out["matches"] = symbols[:500]
    out["symtab_va"] = hex(symtab_va)
    out["strtab_va"] = hex(strtab_va)
    out["strsz"] = strsz
    out["syment"] = syment

    if not symbols:
        out["note"] = (
            "Table dynamique analysée, mais aucun des noms de fonctions "
            "recherchés n'est présent."
        )

    return out


# ------------------------------------------------------------
# COMMUNICATION PS4DEBUG-NG
# ------------------------------------------------------------

def recv_exact(sock, n):

    b = bytearray()

    while len(b) < n:

        part = sock.recv(n - len(b))

        if not part:
            raise ConnectionError(
                f"Connexion interrompue ({len(b)}/{n} octets)"
            )

        b.extend(part)

    return bytes(b)


def send_cmd(sock, cmd, body=b""):

    sock.sendall(
        struct.pack("<III", MAGIC, cmd, len(body)) + body
    )


def read_status(sock):

    status = struct.unpack("<I", recv_exact(sock, 4))[0]

    if status != SUCCESS:
        raise RuntimeError(
            f"Statut PS4 inattendu: 0x{status:08X}"
        )


def c_string(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


# ------------------------------------------------------------
# DECODAGE DES CARTES MEMOIRE SELON LE HEADER LOCAL
# ------------------------------------------------------------

def decode_map_layout(header_info, raw, count):

    fields = {
        f["name"]: f
        for f in header_info["fields"]
    }

    name_field = (
        fields.get("name")
        or fields.get("pathname")
        or fields.get("path")
    )

    required = ["start", "end", "offset", "prot"]

    if not name_field or not all(k in fields for k in required):
        raise ValueError(
            "Header local incomplet pour le décodage des maps."
        )

    size = header_info["size"]
    maps = []

    for i in range(count):

        ent = raw[i * size:(i + 1) * size]
        item = {}

        for key in required:

            f = fields[key]

            item[key] = int.from_bytes(
                ent[f["offset"]:f["offset"] + f["size"]],
                "little"
            )

        f = name_field

        item["name"] = c_string(
            ent[f["offset"]:f["offset"] + f["size"]]
        )

        maps.append(item)

    return maps


# ------------------------------------------------------------
# SNAPSHOT ACTUEL DE LA CONSOLE
# ------------------------------------------------------------

def network_snapshot(elf_info, struct_info):

    net = {"connected": False}

    if os.environ.get("PS4_SKIP_NETWORK") == "1":
        net["skipped"] = "PS4_SKIP_NETWORK=1"
        return net

    try:

        with socket.create_connection(
            (IP, PORT),
            timeout=10
        ) as s:

            s.settimeout(20)
            net["connected"] = True

            # Version du payload
            send_cmd(s, CMD_VERSION)

            n = struct.unpack(
                "<I",
                recv_exact(s, 4)
            )[0]

            if n > 4096:
                raise ValueError(f"Longueur VERSION anormale: {n}")

            net["payload_version"] = recv_exact(
                s, n
            ).decode("utf-8", "replace")

            # Firmware
            send_cmd(s, CMD_FW_VERSION)

            fw_raw = struct.unpack(
                "<H",
                recv_exact(s, 2)
            )[0]

            digits = [
                (fw_raw >> shift) & 0xF
                for shift in (12, 8, 4, 0)
            ]

            fw_bcd = (
                f"{digits[0]}{digits[1]}.{digits[2]}{digits[3]}"
                if all(x < 10 for x in digits) else None
            )

            net["firmware_raw_hex"] = hex(fw_raw)
            net["firmware_bcd"] = fw_bcd

            # Branding
            send_cmd(s, CMD_BRANDING)

            n = struct.unpack(
                "<I",
                recv_exact(s, 4)
            )[0]

            if n > 4096:
                raise ValueError(f"Longueur BRANDING anormale: {n}")

            net["branding"] = recv_exact(
                s, n
            ).decode("utf-8", "replace")

            # Base noyau actuelle
            send_cmd(s, CMD_KERN_BASE)
            read_status(s)

            live_base = struct.unpack(
                "<Q",
                recv_exact(s, 8)
            )[0]

            net["kernel_base"] = hex(live_base)
            net["kernel_base_delta_vs_dump"] = hex(
                live_base - elf_info["base"]
            )
            net["kernel_base_matches_dump"] = (
                live_base == elf_info["base"]
            )

            # Lecture des premiers 4 KiB du noyau
            send_cmd(
                s,
                CMD_KERN_READ,
                struct.pack("<QI", live_base, 0x1000)
            )

            read_status(s)
            live_head = recv_exact(s, 0x1000)

            head_path = OUTDIR / "kernel_live_first_4k.bin"
            head_path.write_bytes(live_head)

            net["kernel_head_sha256"] = sha256(live_head)
            net["kernel_head_elf_magic"] = (
                live_head[:4] == b"\x7fELF"
            )
            net["kernel_head_matches_local_prefix"] = (
                live_head == elf_info["data"][:0x1000]
            )
            net["kernel_head_file"] = str(head_path)

            # Liste des processus
            send_cmd(s, CMD_PROC_LIST)
            read_status(s)

            count = struct.unpack(
                "<I",
                recv_exact(s, 4)
            )[0]

            if count > 5000:
                raise ValueError(
                    f"Nombre de processus anormal: {count}"
                )

            proc_raw = recv_exact(s, count * 36)
            procs = []

            for i in range(count):

                ent = proc_raw[i * 36:(i + 1) * 36]

                procs.append({
                    "name": c_string(ent[:32]),
                    "pid": struct.unpack_from("<i", ent, 32)[0]
                })

            net["process_count"] = count
            net["processes"] = procs

            # Cartes mémoire des processus importants
            if struct_info:

                targets = {
                    "SceShellUI",
                    "SceShellCore",
                    "SceSpkService"
                }

                target_procs = [
                    p for p in procs
                    if p["name"] in targets
                ]

                net["map_struct"] = {
                    "header": struct_info["path"],
                    "size": struct_info["size"],
                    "packed": struct_info["packed"],
                    "fields": struct_info["fields"]
                }

                net["selected_process_maps"] = {}

                for proc in target_procs:

                    pid = proc["pid"]
                    pname = proc["name"]

                    send_cmd(
                        s,
                        CMD_PROC_MAPS,
                        struct.pack("<I", pid)
                    )

                    read_status(s)

                    mcount = struct.unpack(
                        "<I",
                        recv_exact(s, 4)
                    )[0]

                    if mcount > 30000:

                        net["selected_process_maps"][pname] = {
                            "pid": pid,
                            "error": f"Nombre anormal: {mcount}"
                        }

                        continue

                    raw = recv_exact(
                        s,
                        mcount * struct_info["size"]
                    )

                    raw_path = OUTDIR / f"maps_{pname}_{pid}.bin"
                    raw_path.write_bytes(raw)

                    maps = decode_map_layout(
                        struct_info,
                        raw,
                        mcount
                    )

                    names = Counter(
                        m["name"] or "[sans nom]"
                        for m in maps
                    )

                    execs = [
                        m for m in maps
                        if m["prot"] & 4
                    ]

                    net["selected_process_maps"][pname] = {
                        "pid": pid,
                        "count": mcount,
                        "raw_file": str(raw_path),
                        "name_counts": names.most_common(30),
                        "executable_count": len(execs),

                        "executable_first_40": [
                            {
                                "start": hex(m["start"]),
                                "end": hex(m["end"]),
                                "prot": hex(m["prot"]),
                                "name": m["name"]
                            }
                            for m in execs[:40]
                        ],

                        "first_12_regions": [
                            {
                                "start": hex(m["start"]),
                                "end": hex(m["end"]),
                                "offset": hex(m["offset"]),
                                "prot": hex(m["prot"]),
                                "name": m["name"]
                            }
                            for m in maps[:12]
                        ]
                    }

            else:

                net["maps_skipped"] = (
                    "Header local proc_vm_map_entry non trouvé. "
                    "Aucune taille 58/64 supposée."
                )

            # Identification facultative, placée en dernier
            try:

                send_cmd(s, CMD_PROTOCOL_ID)

                net["cmd_bd000502_u16"] = struct.unpack(
                    "<H",
                    recv_exact(s, 2)
                )[0]

            except Exception as info_exc:

                net["cmd_bd000502_error"] = repr(info_exc)

        return net

    except Exception as exc:

        net["error"] = repr(exc)
        return net


# ------------------------------------------------------------
# PROGRAMME PRINCIPAL
# ------------------------------------------------------------

def main():

    section("PS4 SCOUT MASTER - MODE LECTURE SEULE")

    say(f"Cible réseau : {IP}:{PORT}")
    say(f"Dossier rapports : {REPORTS}")

    say(
        "Commandes: VERSION, FW_VERSION, BRANDING, "
        "PROTOCOL_ID, KERN_BASE, KERN_READ, PROC_LIST, PROC_MAPS."
    )

    say(
        "Aucun KERN_WRITE / PROC_WRITE / ATTACH / REBOOT."
    )

    # Fichiers
    section("FICHIERS LOCAUX")

    say(f"ELF complet : {ELF} | existe={ELF.exists()}")
    say(f"JSON Scout : {SCOUT_JSON} | existe={SCOUT_JSON.exists()}")
    say(f"Ancien dump 4K : {SMALL_DUMP} | existe={SMALL_DUMP.exists()}")
    say(f"Sources ps4debug-NG : {SOURCE} | existe={SOURCE.exists()}")
    say(f"Payload local : {PAYLOAD} | existe={PAYLOAD.exists()}")

    if PAYLOAD.exists():

        payload_hash = sha256(PAYLOAD.read_bytes())

        expected_payload_hash = (
            "a23b2ec5808bb6f051be159750588a0c48518701e3605f5069db34bcbab57cdc"
        )

        say(f"SHA256 payload local : {payload_hash}")

        say(
            "Identique au hash précédent : "
            f"{payload_hash == expected_payload_hash}"
        )

        RESULT["local_payload"] = {
            "sha256": payload_hash,
            "matches_previous_hash": payload_hash == expected_payload_hash
        }

    RESULT["paths"] = {
        "elf": str(ELF),
        "scout_json": str(SCOUT_JSON),
        "small_dump": str(SMALL_DUMP),
        "source": str(SOURCE),
        "payload": str(PAYLOAD),
        "output_dir": str(OUTDIR)
    }

    if not ELF.exists():

        say(
            "ERREUR: ELF complet introuvable. "
            "Le script s'arrête après le diagnostic des chemins."
        )

        (OUTDIR / "report.txt").write_text(
            "\n".join(LOG),
            encoding="utf-8"
        )

        return

    # Hash
    section("HASH ET INTEGRITE DU DUMP")

    raw_elf = ELF.read_bytes()
    digest = sha256(raw_elf)

    say(
        f"Taille : {len(raw_elf)} octets "
        f"({len(raw_elf)/1024/1024:.2f} MiB)"
    )

    say(f"SHA256 : {digest}")

    expected_hash = (
        "bfe5b4efae4f025674dc6346eb327bd4b69edb42dbb15895177a6ea51d2ded39"
    )

    say(
        "Hash identique au résultat précédent : "
        f"{digest == expected_hash}"
    )

    RESULT["elf_file"] = {
        "size": len(raw_elf),
        "sha256": digest,
        "matches_previous_hash": digest == expected_hash
    }

    if SMALL_DUMP.exists():

        small = SMALL_DUMP.read_bytes()
        same = raw_elf[:len(small)] == small

        say(
            f"Ancien dump {len(small)} octets = "
            f"préfixe du dump complet : {same}"
        )

        say(f"SHA256 ancien 4K : {sha256(small)}")

        RESULT["small_dump_prefix_match"] = same

    # En-tête et segments
    section("EN-TETE ELF ET PROGRAM HEADERS")

    e = parse_elf(ELF)
    h = e["header"]

    say(
        f"ELF64 little-endian | OSABI={h['osabi']} "
        f"| type={h['type']} | machine={h['machine']}"
    )

    say(f"Entry : {h['entry']:#018x}")
    say(f"Base PT_LOAD : {e['base']:#018x}")
    say(f"Entry - base : {h['entry'] - e['base']:#x}")

    say(
        f"PHDR: offset={h['phoff']:#x}, "
        f"taille={h['phentsize']}, nombre={h['phnum']}"
    )

    say(
        f"Section headers: offset={h['shoff']:#x}, "
        f"nombre={h['shnum']}"
    )

    ptype = {
        0: "NULL",
        1: "LOAD",
        2: "DYNAMIC",
        3: "INTERP",
        4: "NOTE",
        5: "SHLIB",
        6: "PHDR",
        7: "TLS",
        0x61000010: "PT_SCE_RELRO"
    }

    phout = []

    for p in e["phdrs"]:

        flags = "".join([
            "R" if p["flags"] & 4 else "-",
            "W" if p["flags"] & 2 else "-",
            "X" if p["flags"] & 1 else "-"
        ])

        nm = ptype.get(p["type"], hex(p["type"]))

        say(
            f"[{p['index']}] {nm:14} flags={flags} "
            f"off={p['offset']:#x} "
            f"va={p['vaddr']:#018x} "
            f"RVA={p['vaddr']-e['base']:+#x} "
            f"filesz={p['filesz']:#x} "
            f"memsz={p['memsz']:#x} "
            f"align={p['align']:#x}"
            + (" [HORS FICHIER]" if p["out_of_file"] else "")
        )

        if p["memsz"] > p["filesz"]:

            say(
                f"    Mémoire non présente dans le fichier : "
                f"{p['memsz']-p['filesz']:#x} octets ; "
                f"fin mémoire={p['vaddr']+p['memsz']:#018x}"
            )

        phout.append({
            **p,
            "type_name": nm,
            "flags_text": flags,
            **{
                k: hex(p[k])
                for k in (
                    "offset", "vaddr", "paddr",
                    "filesz", "memsz", "align"
                )
            }
        })

    RESULT["elf"] = {
        "header": {
            **h,
            **{
                k: hex(h[k])
                for k in ("entry", "phoff", "shoff")
            }
        },
        "base": hex(e["base"]),
        "program_headers": phout
    }

    # Dynamic
    section("SEGMENT DYNAMIC ET SYMBOLS")

    dyn_result = dynamic_symbol_analysis(e)

    if not dyn_result["tags"]:

        say("Aucune entrée dynamique exploitable.")

    else:

        for item in dyn_result["tags"]:

            say(
                f"{item['name']:20} "
                f"{item['tag']:>12} = {item['value']}"
            )

    say(
        f"Symboles dynamiques comptés : "
        f"{dyn_result.get('symbols_total', 0)}"
    )

    say(
        f"Symboles avec nom : "
        f"{dyn_result.get('symbols_named', 0)}"
    )

    if dyn_result.get("matches"):

        say("Fonctions/symboles correspondant aux mots-clés :")

        for s in dyn_result["matches"]:

            say(
                f"  {s['name']:<34} "
                f"addr={s['value']} "
                f"RVA={s['rva_from_kernel_base']} "
                f"size={s['size']} "
                f"bind={s['bind']} "
                f"type={s['type']}"
            )

    if dyn_result.get("note"):
        say("Diagnostic symboles : " + dyn_result["note"])

    RESULT["dynamic_analysis"] = dyn_result

    # Point d'entrée et chaînes
    section("POINT D'ENTREE ET CHAINES ASCII")

    entry_off = e["va_to_off"](h["entry"], 64)

    if entry_off is not None:

        entry_bytes = e["data"][entry_off:entry_off + 64]

        say(f"Entry file offset : {entry_off:#x}")
        say(
            "64 octets au point d'entrée : "
            + entry_bytes.hex(" ")
        )

        RESULT["entry_bytes"] = {
            "file_offset": hex(entry_off),
            "hex": entry_bytes.hex()
        }

    else:

        say("Point d'entrée non mappable dans les segments présents.")

    keywords = (
        b"FreeBSD", b"Orbis", b"Sony", b"SCE",
        b"Radeon", b"AMD", b"Belize", b"Sce",
        b"kernel", b"GDDR", b"GPU", b"APU"
    )

    found_strings = []

    for m in re.finditer(rb"[\x20-\x7e]{6,}", e["data"]):

        value = m.group().decode("ascii", "replace")

        if any(
            k.lower() in value.lower().encode("ascii", "ignore")
            for k in keywords
        ):

            found_strings.append({
                "offset": hex(m.start()),
                "text": value[:200]
            })

            if len(found_strings) >= 100:
                break

    for item in found_strings:

        say(
            f"STRING {item['offset']}: {item['text']}"
        )

    say(
        f"Chaînes ASCII pertinentes : {len(found_strings)} "
        "(limite 100)"
    )

    RESULT["interesting_strings"] = found_strings

    # Outils ELF
    section("SORTIES READELF / NM")

    commands = [
        ("readelf -lW", ["readelf", "-lW", str(ELF)]),
        ("readelf -dW", ["readelf", "-dW", str(ELF)]),
        ("readelf --dyn-syms", ["readelf", "--dyn-syms", "-W", str(ELF)]),
        ("nm -D", ["nm", "-D", str(ELF)])
    ]

    for label, args in commands:

        out = run_cmd(args)

        say(f"--- {label} ---")

        for line in out.splitlines()[:80]:
            say(line)

    # Sources locales
    section("VERSION DU CODE SOURCE / STRUCTURE MAPS")

    if SOURCE.exists():

        say(
            "Git remote : "
            + run_cmd([
                "git", "-C", str(SOURCE),
                "remote", "-v"
            ]).replace("\n", " | ")
        )

        say(
            "Git commit : "
            + run_cmd([
                "git", "-C", str(SOURCE),
                "rev-parse", "HEAD"
            ])
        )

        say(
            "Git status : "
            + run_cmd([
                "git", "-C", str(SOURCE),
                "status", "--short"
            ]).replace("\n", " | ")[:500]
        )

    struct_info = locate_struct_header()

    if struct_info:

        say(f"Header utilisé : {struct_info['path']}")

        say(
            f"packed={struct_info['packed']} ; "
            f"taille C calculée={struct_info['size']} octets"
        )

        say("Champs et offsets :")

        for f in struct_info["fields"]:

            say(
                f"  {f['name']:<12} "
                f"type={f['type']:<12} "
                f"offset={f['offset']:<3} "
                f"size={f['size']}"
            )

        say(
            "Déclaration source : "
            + struct_info["source_text"].replace("\n", " ")
        )

        RESULT["map_struct_source"] = {
            k: struct_info[k]
            for k in (
                "path", "packed", "size",
                "fields", "source_text"
            )
        }

    else:

        say(
            "ATTENTION: struct proc_vm_map_entry introuvable. "
            "Aucune taille 58/64 octets supposée."
        )

    # Ancien rapport
    section("ANCIEN RAPPORT SCOUT JSON")

    if SCOUT_JSON.exists():

        try:

            j = json.loads(
                SCOUT_JSON.read_text(encoding="utf-8")
            )

            r = j.get("results", j)

            for key in (
                "protocol_version_raw",
                "branding_raw",
                "firmware_raw",
                "platform_id",
                "kernel_base",
                "kernel_base_sample_hex"
            ):

                say(f"{key}: {r.get(key)!r}")

            old_maps = r.get("selected_process_maps", {})

            for name, maps in old_maps.items():
                say(f"Ancien rapport maps {name}: {len(maps)} régions")

            RESULT["previous_scout_metadata"] = {
                k: r.get(k)
                for k in (
                    "protocol_version_raw",
                    "branding_raw",
                    "firmware_raw",
                    "platform_id",
                    "kernel_base",
                    "kernel_base_sample_hex"
                )
            }

            RESULT["previous_map_counts"] = {
                k: len(v)
                for k, v in old_maps.items()
            }

        except Exception as ex:

            say(
                "Impossible de lire le JSON Scout : "
                + repr(ex)
            )

    else:

        say("JSON Scout précédent absent.")

    # Console
    section("INTERROGATION EN DIRECT - LECTURE SEULE")

    net = network_snapshot(e, struct_info)
    RESULT["live"] = net

    if net.get("connected"):

        say(f"Connecté à {IP}:{PORT}")
        say(f"Payload : {net.get('payload_version')}")
        say(f"Branding : {net.get('branding')}")

        say(
            f"Firmware brut : {net.get('firmware_raw_hex')} "
            f"; BCD : {net.get('firmware_bcd')}"
        )

        say(
            "CMD 0xBD000502 uint16 : "
            f"{net.get('cmd_bd000502_u16')}"
        )

        say(f"Base noyau actuelle : {net.get('kernel_base')}")

        say(
            "Delta par rapport au dump : "
            f"{net.get('kernel_base_delta_vs_dump')} "
            f"(base identique={net.get('kernel_base_matches_dump')})"
        )

        say(
            f"SHA256 première page noyau : "
            f"{net.get('kernel_head_sha256')}"
        )

        say(
            "Premiers 4K identiques au dump local : "
            f"{net.get('kernel_head_matches_local_prefix')}"
        )

        say(f"Processus présents : {net.get('process_count')}")

        for proc in net.get("processes", []):

            say(
                f"  PID {proc['pid']:>5}  {proc['name']}"
            )

        for pname in (
            "SceSpkService",
            "SceShellUI",
            "SceShellCore"
        ):

            found = [
                p for p in net.get("processes", [])
                if p["name"] == pname
            ]

            if found:
                say(f"{pname}: PID {found[0]['pid']}")

            info = net.get(
                "selected_process_maps", {}
            ).get(pname)

            if info:

                say(
                    f"  Maps: {info.get('count')} régions; "
                    f"exécutables={info.get('executable_count')}"
                )

                say(
                    "  Noms dominants : "
                    + ", ".join(
                        f"{n}={c}"
                        for n, c in info.get("name_counts", [])[:12]
                    )
                )

                for m in info.get("executable_first_40", [])[:12]:

                    say(
                        f"  EXEC {m['start']}..{m['end']} "
                        f"prot={m['prot']} {m['name']}"
                    )

        if net.get("maps_skipped"):
            say(net["maps_skipped"])

    else:

        say(
            "Connexion/lecture live indisponible : "
            + str(net.get("error", net.get("skipped")))
        )

    # Sauvegarde
    section("RAPPORTS CREES")

    json_path = OUTDIR / "report.json"
    txt_path = OUTDIR / "report.txt"

    say(f"Rapport texte : {txt_path}")
    say(f"Rapport JSON  : {json_path}")
    say(f"Dossier      : {OUTDIR}")

    txt_path.write_text(
        "\n".join(LOG) + "\n",
        encoding="utf-8"
    )

    json_path.write_text(
        json.dumps(RESULT, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(
        "\nJoins report.txt + report.json + "
        "les fichiers maps_*.bin si présents."
    )


if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:
        print("\nInterrompu.")
        raise

    except Exception as exc:
        print(f"\nERREUR FATALE: {exc!r}")
        raise


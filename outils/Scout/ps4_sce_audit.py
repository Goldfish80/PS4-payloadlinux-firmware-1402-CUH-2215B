#!/usr/bin/env python3

import csv
import hashlib
import json
import os
import re
import socket
import struct
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path.home() / "PS4/Linux/Scout"
ELF = Path(os.environ.get(
    "PS4_ELF",
    str(ROOT / "reports/kernel_20261115_full.elf")
))

OUT = ROOT / "reports" / (
    "sce_audit_" + datetime.now().strftime("%Y%m%d_%H%M%S")
)
OUT.mkdir(parents=True, exist_ok=True)

IP = os.environ.get("PS4_IP", "192.0.2.10")
PORT = int(os.environ.get("PS4_PORT", "744"))

PREF = 0xffffffff82200000

TAGS = {
    "STRTAB": (0x61000035, 0x61000037),
    "SYMTAB": (0x61000039, 0x6100003f),
    "RELA":   (0x6100002f, 0x61000031),
    "HASH":   (0x61000025, 0x6100003d),
}

NEEDLES = (
    "copyin", "copyout", "copyinstr",
    "kernel_map", "kernel_pmap",
    "kmem_alloc", "kmem_free",
    "pmap_extract", "pmap_protect",
    "sysent", "printf",
    "sched_pin", "sched_unpin",
    "smp_rendezvous", "icc_query",
    "gc_get_fw", "starsha", "gpu_devid",
    "phys_avail", "allproc",
    "vm_page", "vtophys",
    "amd", "belize", "radeon",
)

LOG = []
SUMMARY = {
    "target_firmware": "14.02",
    "output": str(OUT),
    "tables": {}
}


def say(*items):
    line = " ".join(str(x) for x in items)
    print(line, flush=True)
    LOG.append(line)


def uhex(v):
    return hex(v) if isinstance(v, int) else ""


def stats(b):
    nonzero = sum(bool(x) for x in b)
    blocks = [
        sum(bool(x) for x in b[i:i+4096])
        for i in range(0, len(b), 4096)
    ]

    return {
        "length": len(b),
        "nonzero": nonzero,
        "zeros": len(b) - nonzero,
        "nonzero_blocks": sum(bool(x) for x in blocks),
        "blocks": len(blocks),
        "sha256": hashlib.sha256(b).hexdigest(),
        "first64": b[:64].hex(" "),
        "last32": b[-32:].hex(" "),
    }


def save_tsv(name, rows, columns):
    with (OUT / name).open(
        "w", newline="", encoding="utf-8"
    ) as f:
        w = csv.DictWriter(
            f,
            fieldnames=columns,
            delimiter="\t",
            extrasaction="ignore"
        )
        w.writeheader()
        w.writerows(rows)


def recv_exact(sock, n):
    b = bytearray()

    while len(b) < n:
        part = sock.recv(n - len(b))

        if not part:
            raise ConnectionError(
                "Connexion interrompue"
            )

        b.extend(part)

    return bytes(b)


def request(sock, code, body=b""):
    sock.sendall(
        struct.pack(
            "<III",
            0xFFAABBCC,
            code,
            len(body)
        ) + body
    )


def read_status(sock):
    status = struct.unpack(
        "<I",
        recv_exact(sock, 4)
    )[0]

    if status != 0x80000000:
        raise RuntimeError(
            f"Statut lecture PS4: {status:#x}"
        )


def kern_read(sock, address, n):
    if not 0 < n <= 0x4000:
        raise ValueError(
            "Taille lecture > 16 KiB"
        )

    request(
        sock,
        0xBDCC0002,
        struct.pack("<QI", address, n)
    )

    read_status(sock)
    return recv_exact(sock, n)


def analyze_tables(tables, base, ph, live_base, sock):
    SUMMARY["analyzed"] = True
    say("========== ANALYSE DES TABLES =========")

    def choose(n):
        t = tables.get(n)

        if not t:
            return None, "absente"

        if "live" in t:
            live_nonzero = stats(t["live"])["nonzero"]
            local_nonzero = stats(t["local"])["nonzero"]

            if live_nonzero > local_nonzero:
                return t["live"], "live"

        return t["local"], "dump"

    strtab, origin_str = choose("STRTAB")
    symtab, origin_sym = choose("SYMTAB")
    hashdata, origin_hash = choose("HASH")
    reladata, origin_rela = choose("RELA")

    sources = {
        "STRTAB": origin_str,
        "SYMTAB": origin_sym,
        "HASH": origin_hash,
        "RELA": origin_rela
    }

    say("Sources sélectionnées:", sources)
    SUMMARY["sources"] = sources

    # --------------------------------------------------------
    # STRTAB : EXTRACTION DES CHAINES
    # --------------------------------------------------------

    samples = []

    if strtab is not None:
        for m in re.finditer(
            rb"[\x21-\x7e]{5,}",
            strtab
        ):
            samples.append((
                m.start(),
                m.group()[:120].decode(
                    "ascii", "replace"
                )
            ))

        say(
            "STRTAB chaînes imprimables >=5:",
            len(samples)
        )

        for off, s in samples[:30]:
            say("  chaîne", hex(off), repr(s))

        save_tsv(
            "strings.tsv",
            [
                {
                    "offset": hex(x),
                    "value": v
                }
                for x, v in samples
            ],
            ["offset", "value"]
        )

    # --------------------------------------------------------
    # SYMTAB : RECUPERATION DES SYMBOLES
    # --------------------------------------------------------

    rows = []
    candidates = []

    named = 0
    defined_funcs = 0
    valid_refs = 0
    invalid_refs = 0
    nonzero_records = 0

    if symtab is not None and strtab is not None:
        count = len(symtab) // 24

        for i in range(count):
            raw = symtab[i*24:(i+1)*24]

            if any(raw):
                nonzero_records += 1

            (
                st_name,
                info,
                other,
                shndx,
                value,
                size
            ) = struct.unpack(
                "<IBBHQQ",
                raw
            )

            label = ""

            if st_name < len(strtab):
                end = strtab.find(
                    b"\0",
                    st_name
                )

                if end >= 0:
                    label = strtab[
                        st_name:end
                    ].decode(
                        "utf-8",
                        "replace"
                    )

                valid_refs += 1
            else:
                invalid_refs += 1

            if label:
                named += 1

            typ = info & 15

            if typ == 2 and shndx != 0:
                defined_funcs += 1

            # Tester plusieurs conventions d'adressage :
            # LINK, RUNTIME et RVA.
            rt = None
            loc = ""
            mode = ""

            hypotheses = [
                ("LINK", value + (base - PREF)),
                ("RUNTIME", value)
            ]

            if value < 0x10000000:
                hypotheses.append((
                    "RVA",
                    base + value
                ))

            for candidate_mode, candidate_addr in hypotheses:

                for p in ph:

                    if p["type"] not in (
                        1, 0x61000010
                    ):
                        continue

                    if (
                        p["va"] <= candidate_addr
                        < p["va"] + p["memsz"]
                    ):
                        rt = candidate_addr
                        mode = candidate_mode

                        loc = (
                            "RX"
                            if p["flags"] & 1
                            else "DATA"
                        )

                        break

                if loc:
                    break

            row = {
                "index": i,
                "name": label,
                "name_index": hex(st_name),
                "type": typ,
                "bind": info >> 4,
                "shndx": shndx,
                "st_value": hex(value),
                "address_mode": mode,
                "rva": (
                    hex(rt - base)
                    if rt is not None else ""
                ),
                "runtime_dump": (
                    hex(rt)
                    if rt is not None else ""
                ),
                "size": hex(size),
                "segment": loc,
                "raw": raw.hex()
            }

            rows.append(row)

            if (
                label
                and loc
                and any(
                    k in label.lower()
                    for k in NEEDLES
                )
            ):
                candidates.append(row)

        say(
            "SYMTAB enregistrements=", count,
            "nonzero=", nonzero_records,
            "st_name valide=", valid_refs,
            "hors STRTAB=", invalid_refs,
            "noms=", named,
            "fonctions définies=", defined_funcs,
            "candidats=", len(candidates)
        )

        for r in rows[:12]:
            say(
                "  symbole brut",
                r["index"],
                r["name_index"],
                r["st_value"],
                r["type"],
                r["raw"]
            )

        for r in candidates[:80]:
            say(
                "  CANDIDAT",
                r["name"],
                "RVA", r["rva"],
                "segment", r["segment"]
            )

        cols = [
            "index", "name", "name_index",
            "type", "bind", "shndx",
            "st_value", "address_mode",
            "rva", "runtime_dump",
            "size", "segment", "raw"
        ]

        save_tsv(
            "symbols.tsv",
            rows,
            cols
        )

        save_tsv(
            "candidates.tsv",
            candidates,
            cols
        )

        SUMMARY["symbols"] = {
            "records": count,
            "nonzero_records": nonzero_records,
            "valid_name_indices": valid_refs,
            "invalid_name_indices": invalid_refs,
            "named": named,
            "defined_functions": defined_funcs,
            "candidates": len(candidates)
        }

    # --------------------------------------------------------
    # HASH SONY - CORRECTION DES 4 OCTETS RESTANTS
    # --------------------------------------------------------

    if hashdata is not None:
        tail = len(hashdata) % 8

        say(
            "HASH taille=", hex(len(hashdata)),
            "entrees_8_octets=", len(hashdata) // 8,
            "reste=", tail,
            "octets_fin=",
            hashdata[-tail:].hex() if tail else ""
        )

        if len(hashdata) >= 8:
            say(
                "HASH premiers uint32:",
                struct.unpack_from(
                    "<II",
                    hashdata
                )
            )

        say(
            "HASH premiers 64 octets:",
            hashdata[:64].hex(" ")
        )

    # --------------------------------------------------------
    # RELA : INVENTAIRE DES RELOCATIONS
    # --------------------------------------------------------

    if reladata is not None:
        types = Counter()
        nonzero = 0
        examples = []

        for i in range(len(reladata) // 24):
            off, info, addend = struct.unpack_from(
                "<QQq",
                reladata,
                i * 24
            )

            if (off, info, addend) != (0, 0, 0):
                nonzero += 1
                types[info & 0xffffffff] += 1

                if len(examples) < 12:
                    examples.append((
                        hex(off),
                        hex(info),
                        hex(addend & ((1 << 64) - 1))
                    ))

        say(
            "RELA entrées=",
            len(reladata) // 24,
            "nonzero=", nonzero,
            "types=", types.most_common(15)
        )

        for ex in examples:
            say("  RELA", ex)

        SUMMARY["relocations"] = {
            "records": len(reladata) // 24,
            "nonzero_records": nonzero,
            "types": dict(types)
        }

    # --------------------------------------------------------
    # VALIDATION DES FONCTIONS EN LECTURE SEULE
    # --------------------------------------------------------

    validations = []

    if sock is not None and live_base is not None:
        for row in candidates:

            if len(validations) >= 12:
                break

            if (
                row["type"] != 2
                or row["shndx"] == 0
                or row["segment"] != "RX"
            ):
                continue

            rva = int(row["rva"], 16)
            target = live_base + rva

            p = next(
                (
                    p for p in ph
                    if (
                        p["type"] == 1
                        and p["flags"] & 1
                        and p["va"] <= base + rva
                        and base + rva + 16
                        <= p["va"] + p["filesz"]
                    )
                ),
                None
            )

            if not p:
                continue

            file_offset = (
                p["off"]
                + base + rva - p["va"]
            )

            try:
                live_bytes = kern_read(
                    sock,
                    target,
                    16
                )

                with ELF.open("rb") as f:
                    f.seek(file_offset)
                    expected = f.read(16)

                same = live_bytes == expected

                validations.append({
                    "name": row["name"],
                    "rva": row["rva"],
                    "address": hex(target),
                    "match_dump": same,
                    "live_hex": live_bytes.hex(),
                    "dump_hex": expected.hex()
                })

                say(
                    "  VALIDATION",
                    row["name"],
                    row["rva"],
                    "octets identiques=", same
                )

            except Exception as exc:
                say(
                    "  ERREUR VALIDATION",
                    row["name"],
                    repr(exc)
                )

    SUMMARY["validation"] = validations

    save_tsv(
        "validation.tsv",
        validations,
        [
            "name", "rva", "address",
            "match_dump", "live_hex", "dump_hex"
        ]
    )

    if not candidates:
        say(
            "CONCLUSION: aucun offset de fonction "
            "NOMMEE vérifié."
        )
        say(
            "Prochaine piste: analyse statique "
            "du noyau avec Ghidra et signatures."
        )


def main():

    say("========== SCE AUDIT / LECTURE SEULE ==========")
    say("ELF:", ELF)

    data = ELF.read_bytes()

    if (
        data[:4] != b"\x7fELF"
        or data[4:6] != b"\x02\x01"
    ):
        raise ValueError(
            "Pas un ELF64 little endian"
        )

    sha = hashlib.sha256(data).hexdigest()

    SUMMARY["elf"] = {
        "path": str(ELF),
        "length": len(data),
        "sha256": sha
    }

    say(
        "Taille:", len(data),
        "SHA256:", sha
    )

    expected_hash = (
        "bfe5b4efae4f025674dc6346eb327bd4b69edb42dbb15895177a6ea51d2ded39"
    )

    if sha != expected_hash:
        say(
            "AVERTISSEMENT: SHA256 différent "
            "du dump précédent"
        )

    (
        _, _, _, _, entry, phoff, _, _, _,
        phentsize, phnum, *_
    ) = struct.unpack_from(
        "<16sHHIQQQIHHHHHH",
        data
    )

    if (
        phnum > 64
        or phentsize < 56
        or phoff + phnum * phentsize > len(data)
    ):
        raise ValueError("PHDR invalide")

    ph = []

    for i in range(phnum):
        a = struct.unpack_from(
            "<IIQQQQQQ",
            data,
            phoff + i * phentsize
        )

        p = dict(zip(
            (
                "type", "flags", "off", "va",
                "pa", "filesz", "memsz", "align"
            ),
            a
        ))

        if p["off"] + p["filesz"] > len(data):
            raise ValueError(
                "Segment hors fichier"
            )

        ph.append(p)

    base = min(
        p["va"]
        for p in ph
        if p["type"] == 1
    )

    slide = base - PREF

    SUMMARY["bases"] = {
        "preferred": uhex(PREF),
        "dump": uhex(base),
        "slide": uhex(slide),
        "entry_rva": uhex(entry - base)
    }

    say(
        "Base dump:", hex(base),
        "base link:", hex(PREF),
        "slide:", hex(slide),
        "entry RVA:", hex(entry - base)
    )

    dynseg = next(
        p for p in ph
        if p["type"] == 2
    )

    dyn = {}

    for i in range(
        0,
        dynseg["filesz"],
        16
    ):
        tag, val = struct.unpack_from(
            "<QQ",
            data,
            dynseg["off"] + i
        )

        if tag == 0:
            break

        dyn[tag] = val

    def mapfile(addr, n):
        for p in ph:

            if p["type"] not in (1, 0x61000010):
                continue

            if (
                p["va"] <= addr
                and addr + n
                <= p["va"] + p["filesz"]
            ):
                return (
                    p["off"] + addr - p["va"]
                )

        return None

    tables = {}

    # --------------------------------------------------------
    # EXTRACTION LOCALE DES QUATRE TABLES SONY
    # --------------------------------------------------------

    for name, (taddr, tsize) in TAGS.items():

        if taddr not in dyn or tsize not in dyn:
            say(name, "absent")
            continue

        addr = dyn[taddr] + slide
        size = dyn[tsize]

        off = mapfile(addr, size)

        if off is None:
            raise ValueError(
                f"{name} non mappé à "
                f"{addr:#x} (taille {size:#x})"
            )

        chunk = data[off:off + size]

        tables[name] = {
            "address": addr,
            "offset": off,
            "size": size,
            "local": chunk
        }

        (
            OUT / f"{name.lower()}_local.bin"
        ).write_bytes(chunk)

        s = stats(chunk)

        SUMMARY["tables"][name] = {
            "link_address": uhex(dyn[taddr]),
            "runtime_address_dump": uhex(addr),
            "file_offset": uhex(off),
            "size": uhex(size),
            "local_stats": s
        }

        say(
            f"{name:6}",
            f"lien={dyn[taddr]:#x}",
            f"live_dump={addr:#x}",
            f"fichier={off:#x}",
            f"taille={size:#x}",
            f"nonzero={s['nonzero']}/{size}"
        )

        say(
            "        premiers octets:",
            s["first64"]
        )

    # --------------------------------------------------------
    # LECTURE DIRECTE SUR LA PS4
    # --------------------------------------------------------

    live = None

    if os.environ.get("PS4_SKIP_NETWORK") == "1":
        say(
            "Réseau désactivé "
            "(PS4_SKIP_NETWORK=1)"
        )

    else:
        try:
            with socket.create_connection(
                (IP, PORT),
                timeout=8
            ) as sock:

                sock.settimeout(25)

                request(sock, 0xBDCC0001)
                read_status(sock)

                live_base = struct.unpack(
                    "<Q",
                    recv_exact(sock, 8)
                )[0]

                head = kern_read(
                    sock,
                    live_base,
                    64
                )

                if head[:4] != b"\x7fELF":
                    raise ValueError(
                        "Base live sans signature ELF"
                    )

                live = {
                    "kernel_base": uhex(live_base),
                    "slide": uhex(live_base - PREF),
                    "tables": {}
                }

                say(
                    "Base live:", hex(live_base),
                    "écart avec dump:",
                    hex(live_base - base)
                )

                for name, t in tables.items():

                    address = (
                        live_base
                        + t["address"]
                        - base
                    )

                    chunks = []

                    for pos in range(
                        0,
                        t["size"],
                        0x4000
                    ):
                        n = min(
                            0x4000,
                            t["size"] - pos
                        )

                        chunks.append(
                            kern_read(
                                sock,
                                address + pos,
                                n
                            )
                        )

                    b = b"".join(chunks)
                    t["live"] = b

                    (
                        OUT / f"{name.lower()}_live.bin"
                    ).write_bytes(b)

                    s = stats(b)

                    mismatch = sum(
                        a != c
                        for a, c in zip(
                            t["local"],
                            b
                        )
                    )

                    live["tables"][name] = {
                        "stats": s,
                        "mismatched_bytes": mismatch
                    }

                    say(
                        f"{name:6}",
                        f"live nonzero={s['nonzero']}/{len(b)}",
                        f"diff_vs_dump={mismatch}"
                    )

                    if mismatch:
                        for i, (a, c) in enumerate(
                            zip(t["local"], b)
                        ):
                            if a != c:
                                say(
                                    "    première différence:",
                                    hex(i),
                                    "dump=", hex(a),
                                    "live=", hex(c)
                                )
                                break

                analyze_tables(
                    tables,
                    base,
                    ph,
                    live_base,
                    sock
                )

        except Exception as exc:
            say(
                "ATTENTION: lecture live interrompue:",
                repr(exc)
            )

            if "analyzed" not in SUMMARY:
                analyze_tables(
                    tables, base, ph,
                    None, None
                )

    if "analyzed" not in SUMMARY:
        analyze_tables(
            tables, base, ph,
            None, None
        )

    SUMMARY["live"] = live

    say("========== FIN ==========")
    say("Rapport:", OUT / "summary.txt")
    say("JSON:", OUT / "summary.json")

    (
        OUT / "summary.txt"
    ).write_text(
        "\n".join(LOG) + "\n",
        encoding="utf-8"
    )

    (
        OUT / "summary.json"
    ).write_text(
        json.dumps(
            SUMMARY,
            ensure_ascii=False,
            indent=2
        ),
        encoding="utf-8"
    )


if __name__ == "__main__":
    try:
        main()

    except Exception as e:
        say(
            "ERREUR FATALE:",
            repr(e)
        )

        (
            OUT / "summary.txt"
        ).write_text(
            "\n".join(LOG) + "\n",
            encoding="utf-8"
        )

        (
            OUT / "summary.json"
        ).write_text(
            json.dumps(
                SUMMARY,
                indent=2,
                ensure_ascii=False
            ),
            encoding="utf-8"
        )

        raise

#!/usr/bin/env python3
"""Catalogue reproductible du dump local. Aucune connexion ni écriture console."""
import csv
import hashlib
import json
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = ROOT / 'reports/kernel_20261115_full.elf'
    data = source.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little endian attendu')
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    phoff, phsize, phnum = header[5], header[9], header[10]
    if phsize < 56 or phoff + phsize * phnum > len(data):
        raise ValueError('Program headers invalides')
    segments = []
    dynamic = {}
    for i in range(phnum):
        typ, flags, off, va, _, size, mem, align = struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize)
        if off + size > len(data):
            raise ValueError('Segment tronqué')
        segments.append(dict(type=typ, flags=flags, offset=off, va=va, filesz=size, memsz=mem, align=align))
        if typ == 2:
            for pos in range(off, off+size-15, 16):
                tag, value = struct.unpack_from('<QQ', data, pos)
                if not tag:
                    break
                dynamic[tag] = value
    base = min(s['va'] for s in segments if s['type'] == 1)
    # Cette base de lien est spécifique au dump et aux outils locaux existants.
    preferred = 0xffffffff82200000
    mapped = [s for s in segments if s['type'] in (1, 0x61000010)]

    def locate(rva, length=1):
        for s in mapped:
            delta = base+rva-s['va']
            if 0 <= delta and delta+length <= s['filesz']:
                return s['offset']+delta, s
        return None, None

    out = ROOT / 'reports' / datetime.now(timezone.utc).strftime('catalog_%Y%m%d_%H%M%S')
    out.mkdir(parents=True)

    def save(name, rows, fields):
        with (out/name).open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t')
            writer.writeheader()
            writer.writerows(rows)

    strings = []
    string_at = {}
    for s in mapped:
        for match in re.finditer(rb'[\x20-\x7e]{6,}\x00', data[s['offset']:s['offset']+s['filesz']]):
            off = s['offset'] + match.start()
            rva = s['va']-base+match.start()
            value = match.group()[:-1].decode('ascii')
            string_at[rva] = value
            strings.append(dict(file_offset=hex(off), rva=hex(rva), dump_address=hex(base+rva), text=value))
    save('strings.tsv', strings, ['file_offset', 'rva', 'dump_address', 'text'])
    relocations, references = [], []
    types = Counter()
    rel_off, _ = locate(dynamic[0x6100002f]-preferred, dynamic[0x61000031])
    if rel_off is None or dynamic.get(0x61000033) != 24 or dynamic[0x61000031] % 24:
        raise ValueError('Table RELA invalide')
    for pos in range(rel_off, rel_off+dynamic[0x61000031], 24):
        address, info, addend = struct.unpack_from('<QQQ', data, pos)
        typ = info & 0xffffffff
        types[typ] += 1
        if typ != 8:
            continue
        target, dest = address-preferred, addend-preferred
        off, segment = locate(dest)
        target_off, _ = locate(target, 8)
        actual = struct.unpack_from('<Q', data, target_off)[0] if target_off is not None else None
        row = dict(slot_rva=hex(target), pointee_rva=hex(dest), pointee_file_offset=hex(off) if off is not None else '', executable=bool(segment and segment['flags'] & 1), stored_value=hex(actual) if actual is not None else '', matches_dump_slide=actual == base+dest if actual is not None else '', string=string_at.get(dest, ''))
        relocations.append(row)
        if row['string']:
            references.append(row)
    fields = ['slot_rva', 'pointee_rva', 'pointee_file_offset', 'executable', 'stored_value', 'matches_dump_slide', 'string']
    save('relocations.tsv', relocations, fields)
    save('string_references.tsv', references, fields)
    executable = Counter(r['pointee_rva'] for r in relocations if r['executable'])
    save('code_pointer_candidates.tsv', [dict(rva=rva, references=n, status='pointeur vers segment executable; fonction non identifiee') for rva, n in executable.most_common()], ['rva', 'references', 'status'])
    protocol = ROOT / 'upstream/ps4debug-NG/debugger/include/protocol.h'
    commands = [dict(name=m[1], value=m[2], source_line=i) for i, line in enumerate(protocol.read_text().splitlines(), 1) if (m := re.match(r'#define\s+(CMD_\w+)\s+(0x[0-9A-Fa-f]+)\b', line))]
    save('protocol_constants.tsv', commands, ['name', 'value', 'source_line'])
    summary = dict(source=str(source), sha256=hashlib.sha256(data).hexdigest(), dump_base=hex(base), preferred_base_assumed=hex(preferred), entry_rva=hex(header[4]-base), strings=len(strings), relocations=len(relocations), relocation_types=dict(types), string_references=len(references), unique_code_pointer_candidates=len(executable), matching_relocated_slots=sum(r['matches_dump_slide'] is True for r in relocations), segments=segments, network_status='Local TCP probes rejected: PermissionError EPERM; console state unknown', live_verified=False)
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    (out/'README.md').write_text(f'''# Catalogue statique PS4

Dump SHA256 : `{summary['sha256']}`.
Base dans le dump : `{hex(base)}` ; entrée RVA `{summary['entry_rva']}`.

Extraction : {len(strings)} chaînes ASCII terminées par NUL, {len(relocations)} relocations relatives,
{len(references)} références exactes vers des chaînes et {len(executable)} cibles distinctes dans des segments exécutables.
Les pointeurs de code sont des candidats, sans nom de fonction démontré.
Les références sont issues des relocations, pas d'un désassemblage des instructions.
Les chaînes peuvent aussi provenir de suites d'octets accidentellement imprimables.

Les adresses absolues concernent le dump historique, pas une session actuelle.
Les RVA tiennent compte des segments : un offset fichier n'est pas toujours un RVA.
La base de lien 0xffffffff82200000 est reprise des analyseurs locaux.
La comparaison des valeurs des slots avec la base du dump est fournie par ligne.
Les symboles et leurs noms sont effacés dans le dump (voir audit SCE).
Les constantes du protocole décrivent le code source local ; elles ne prouvent pas l'accès actuel.

Réseau : les essais TCP ont échoué avec EPERM dans cet environnement.
Aucune validation en direct ni modification de la PS4 effectuée.

Reproduction : `python Scout/host/offline_catalog.py` depuis le projet.
Diagnostic en direct depuis un terminal disposant de l'accès réseau :
`PS4_IP=192.0.2.10 PS4_PORT=744 python Scout/host/ps4_scout_master.py`.
''')
    print(json.dumps({k:v for k,v in summary.items() if k != 'segments'}, indent=2))
    print(out)


if __name__ == '__main__':
    main()

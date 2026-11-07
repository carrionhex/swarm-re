#!/usr/bin/env python3
"""carrion_ingest.py — CarrionHex Stage-0 classification cascade. Milestone B.1.
Queries formats.json registry; structural validation via LIEF (soft dep);
container recursion with dedup gate (chx_cache); capstone trial-lift (soft dep);
writes file_format/arch/entropy/compiler/is_stripped into the bridge + verdict.

usage:
  carrion_ingest.py one <file>            classify a single path (stdout)
  carrion_ingest.py sweep                 classify all UNKNOWN artifacts in DB
  carrion_ingest.py histogram             coverage rollup (the G2 receipt)
"""
import sys, os, json, math, struct, signal, sqlite3, argparse, subprocess
from pathlib import Path

ROOT = os.path.expanduser('~/carrion_cache')
DB = os.path.join(ROOT, 'index.db')
BLOBS = os.path.join(ROOT, 'blobs')
CARVE = os.path.expanduser('~/carrion_carve')
REGISTRY = json.load(open(os.path.join(ROOT, 'formats.json')))
FORMATS = REGISTRY['formats']
MAX_DEPTH = 3

try:
    import lief
except Exception:
    lief = None
try:
    import capstone
except Exception:
    capstone = None

# ---------- utilities ----------

def shannon_entropy(path, sample=65536):
    try:
        with open(path, 'rb') as f:
            buf = f.read(sample)
    except Exception:
        return None
    if not buf:
        return 0.0
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    return round(-sum((c / n) * math.log2(c / n) for c in freq if c), 3)

def db_conn():
    conn = sqlite3.connect(DB)
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def blob_path(sha):
    return os.path.join(BLOBS, sha[:2], sha)

def note(sha, lane, summary):
    conn = db_conn()
    aid = conn.execute("SELECT artifact_id FROM artifacts WHERE sha256=?", (sha,)).fetchone()
    conn.execute("INSERT INTO verdicts(artifact_id,analyst_seat,summary,created_at) VALUES(?,?,?,?)",
                 (aid[0] if aid else None, lane, summary, __import__('time').time()))
    conn.commit()
    conn.close()

def mark(sha, fmt=None, arch=None, compiler=None, stripped=None, entropy=None):
    conn = db_conn()
    sets, vals = [], []
    for col, v in (('file_format', fmt), ('arch', arch), ('compiler', compiler),
                   ('is_stripped', stripped), ('entropy', entropy)):
        if v is not None:
            sets.append(f"{col}=?")
            vals.append(v)
    if sets:
        vals.append(sha)
        conn.execute(f"UPDATE artifacts SET {', '.join(sets)} WHERE sha256=?", vals)
    conn.commit()
    conn.close()

def add_to_cache(path, tags='carve-child'):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    sha = h.hexdigest()
    try:
        subprocess.run(['python3', os.path.join(ROOT, 'chx_cache.py'), 'add', path, '--tags', tags],
                       capture_output=True, text=True, timeout=120)
    except Exception:
        pass
    return sha

# ---------- stage 0.1: magic + structure ----------

def classify_header(path):
    """Return (format_id, detail_dict, confidence)."""
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as f:
            head = f.read(64)
            f.seek(max(0, size - 2048))
            tail = f.read(2048) if size > 2048 else b''
    except Exception:
        return 'ERROR', {}, 'none'

    h = head
    # ordered manual ladder — exceptions first, then generic
    if h.startswith(b'\x7fELF'):
        return validate_elf(path, size)
    if h.startswith(b'MZ'):
        return validate_pe(path, size, head)
    if h[:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe'):
        return 'MACHO', {'arch_hint': h[:4].hex()}, 'magic'
    if h[:4] == b'\xca\xfe\xba\xbe':
        nfat = struct.unpack('>I', h[4:8])[0]
        if nfat < 0x1000:
            return 'MACHO_FAT', {'slices': nfat}, 'magic'
        return 'JAVA_CLASS', {'major': nfat}, 'magic'
    if h.startswith(b'dex\n'):
        return 'DEX', {}, 'magic'
    if h.startswith(b'\x00asm'):
        return 'WASM', {}, 'magic'
    if h.startswith(b'\x1bLua'):
        return 'LUA_LUAC', {}, 'magic'
    if h.startswith(b'\x1bLJ'):
        return 'LUAJIT_LJBC', {}, 'magic'
    if h.startswith(b'\xc6\x1f\xbc\x03') or h.startswith(b'\xc6\x1f\xbc\x04'):
        return 'HERMES_HBC', {}, 'magic'
    if h[:2] == b'\x1f\x8b':
        return 'GZIP_SINGLE', {}, 'magic'
    if h.startswith(b'\xfd7zXZ\x00'):
        return 'XZ_STREAM', {}, 'magic'
    if len(h) >= 262 and h[257:262] == b'ustar':
        return 'TAR', {}, 'magic'
    if h.startswith(b'hsqs') or h.startswith(b'sqsh') or h.startswith(b'qshs'):
        return 'SQUASHFS', {}, 'magic'
    if h[:4] == b'\x27\x05\x19\x56':
        return 'UBOOT_LEGACY', {}, 'magic'
    if h[:4] == b'\xd0\x0d\xfe\xed':
        return 'DTB_OR_FIT', {'note': 'dtc check disambiguates'}, 'magic'
    if h.startswith(b'070701') or h.startswith(b'070702'):
        return 'CPIO', {}, 'magic'
    if h.startswith(b'070707') or h.startswith(b'q\x71\x93q') or h[:8] == b'-rom1fs-':
        return 'ROMFS', {}, 'magic'
    if len(head) >= 48 and head[40:44] == b'_FVH':
        return 'UEFI_FV', {}, 'magic@0x28'
    if h.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
        return 'OLE_CFB', {}, 'magic'
    if h.startswith(b'UBI#'):
        return 'UBIFS', {'layer': 'ubi'}, 'magic'
    if h.startswith(b'UBI!'):
        return 'UBIFS', {'layer': 'ubifs'}, 'magic'
    # pyc: u16 magic from the python version table (3.x >= 0x0A0D range check)
    if len(h) >= 4 and h[2:4] == b'\x0d\x0a':
        magic = struct.unpack('<H', h[:2])[0]
        if 1500 <= magic <= 3600:
            return 'PYC', {'magic': magic, 'pyver': pyc_version(magic)}, 'magic'
    # zip family + disambiguation ladder
    if h.startswith(b'PK\x03\x04') or h.startswith(b'PK\x05\x06') or h.startswith(b'PK\x07\x08'):
        return zip_ladder(path, size)
    # scanned patterns (bounded)
    if b'MEI\x0c\x0b\x0a\x0b\x0e' in tail or b'MEI\x0c\x0b\x0a\x0b\x0e' in head:
        return 'PYINSTALLER', {}, 'pattern'
    if b'\xef\xbe\xad\xdeNullsoft' in head or b'NullsoftInst' in head[:1024]:
        return 'NSIS', {}, 'pattern'
    if b'Inno Setup' in head[:1024]:
        return 'INNO_SETUP', {}, 'pattern'
    return None, {'size': size}, 'none'

PYC_TABLE = {  # subset: magic -> version
    3390: '3.7', 3391: '3.7', 3392: '3.7', 3393: '3.7',
    3400: '3.8', 3401: '3.8', 3410: '3.8',
    3420: '3.9', 3421: '3.9', 3422: '3.9', 3423: '3.9', 3424: '3.9',
    3430: '3.10', 3431: '3.10', 3432: '3.10', 3433: '3.10', 3434: '3.10', 3435: '3.10',
    3450: '3.11', 3451: '3.11', 3452: '3.11', 3453: '3.11', 3454: '3.11', 3455: '3.11',
    3490: '3.12', 3491: '3.12', 3492: '3.12', 3493: '3.12', 3494: '3.12', 3495: '3.12',
}
def pyc_version(magic):
    return PYC_TABLE.get(magic, 'unknown-%d' % magic)

def validate_elf(path, size):
    with open(path, 'rb') as f:
        h = f.read(64)
    if len(h) < 20:
        return 'ELF', {'truncated': True}, 'magic'
    ei_class = h[4]; ei_data = h[5]
    bits = '64' if ei_class == 2 else '32'
    endian = '<' if ei_data == 1 else '>'
    machine = struct.unpack(endian + 'H', h[18:20])[0]
    arch = {0x03: 'x86', 0x28: 'arm', 0x3E: 'x86_64', 0xB7: 'aarch64',
            0x08: 'mips', 0xF3: 'riscv64', 0x14: 'ppc', 0x15: 'ppc64'}.get(machine, 'mach-0x%x' % machine)
    stripped = None; compiler = None
    if lief is not None and size < 256 * 1024 * 1024:
        try:
            signal.alarm(30)
            ef = lief.parse(path)
            signal.alarm(0)
            if ef is not None:
                stripped = int(not (getattr(ef, 'symtab_symbols', None) or getattr(ef, 'static_symbols', None)
                                    or ef.dynamic_symbols))
                compiler = guess_compiler_lief(ef)
                return 'ELF', {'arch': arch, 'bits': bits, 'endian': 'le' if ei_data == 1 else 'be',
                               'stripped': bool(stripped), 'compiler': compiler}, 'lief'
        except Exception:
            signal.alarm(0)
    return 'ELF', {'arch': arch, 'bits': bits, 'endian': 'le' if ei_data == 1 else 'be'}, 'magic'

def guess_compiler_lief(ef):
    try:
        comment = b''
        for s in (ef.sections or []):
            if getattr(s, 'name', '') == '.comment':
                comment = bytes(s.content[:200])
                break
        for needle, name in ((b'GCC', 'gcc'), (b'clang', 'clang'), (b'rustc', 'rustc'),
                             (b'Go', 'go'), (b'ghc', 'ghc')):
            if needle in comment:
                return name
        if comment:
            return 'unknown:' + comment.split(b'\x00')[0][:24].decode('latin1', 'replace')
    except Exception:
        pass
    return None

def validate_pe(path, size, head):
    if size < 0x40:
        return 'MSDOS_MZ', {}, 'magic'
    e_lfanew = struct.unpack('<I', head[0x3C:0x40])[0]
    if e_lfanew + 24 > size or e_lfanew > size - 4:
        return 'MSDOS_MZ', {'e_lfanew': e_lfanew}, 'magic'
    with open(path, 'rb') as f:
        f.seek(e_lfanew)
        sig = f.read(24)
    if sig[:4] != b'PE\x00\x00':
        return 'MSDOS_MZ', {}, 'magic'
    machine = struct.unpack('<H', sig[4:6])[0]
    arch = {0x014c: 'x86', 0x8664: 'x86_64', 0x01c0: 'arm', 0x01c4: 'armv7',
            0xaa64: 'aarch64'}.get(machine, 'mach-0x%x' % machine)
    optsize = struct.unpack('<H', sig[16:18])[0]
    with open(path, 'rb') as f:
        f.seek(e_lfanew + 24)
        opth = f.read(min(optsize, 240))
    is_dotnet = False; is_pe32plus = False
    if len(opth) >= 96:
        opt_magic = struct.unpack('<H', opth[:2])[0]
        is_pe32plus = (opt_magic == 0x20B)
        dd_off = 96 if opt_magic == 0x10B else 112
        if opt_magic in (0x10B, 0x20B) and len(opth) >= dd_off + 15 * 8:
            clr = struct.unpack('<I', opth[dd_off + 14 * 8: dd_off + 14 * 8 + 4])[0]
            is_dotnet = clr != 0
    if is_dotnet:
        return 'DOTNET_PE', {'arch': arch, 'pe32plus': is_pe32plus}, 'struct'
    stripped = None; compiler = None
    if lief is not None and size < 256 * 1024 * 1024:
        try:
            signal.alarm(30)
            pe = lief.parse(path)
            signal.alarm(0)
            if pe is not None:
                syms = list(pe.symbols or [])
                stripped = int(len(syms) == 0)
        except Exception:
            signal.alarm(0)
    return 'PE32', {'arch': arch, 'pe32plus': is_pe32plus,
                    'bits': '64' if is_pe32plus else '32'}, 'struct' if lief is None else 'lief'

def zip_ladder(path, size):
    import zipfile
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()[:200]
        zf.close()
    except Exception:
        return 'ZIP_GENERIC', {'broken': True}, 'magic'
    low = set(names)
    if any(n.startswith('Payload/') and n.endswith('.app/') for n in low):
        return 'IPA', {'entries': len(low)}, 'ladder'
    if 'AndroidManifest.xml' in low or any(n.endswith('classes.dex') for n in low):
        return 'APK', {'entries': len(low)}, 'ladder'
    if 'manifest/AndroidManifest.xml' in low or any(n.endswith('.pb') for n in low):
        return 'AAB', {'entries': len(low)}, 'ladder'
    if any(n.endswith('.asar') for n in low) or 'package.json' in low:
        return 'ASAR_BUNDLE', {'entries': len(low)}, 'ladder'
    if 'META-INF/MANIFEST.MF' in low and any(n.endswith('.class') for n in low):
        return 'JAR', {'entries': len(low)}, 'ladder'
    return 'ZIP_GENERIC', {'entries': len(low)}, 'magic'

# ---------- stage 0.2: container recursion ----------

EXTRACTABLE = {'ZIP_GENERIC', 'APK', 'IPA', 'AAB', 'JAR', 'TAR', 'GZIP_SINGLE', 'XZ_STREAM', 'CPIO', 'PYINSTALLER', 'ASAR_BUNDLE', 'MSI'}

def extract_children(path, fmt, out_dir):
    """Best-effort extraction; returns list of child paths."""
    children = []
    try:
        if fmt in ('ZIP_GENERIC', 'APK', 'IPA', 'AAB', 'JAR', 'ASAR_BUNDLE'):
            import zipfile
            with zipfile.ZipFile(path) as zf:
                zf.extractall(out_dir, members=[m for m in zf.namelist()][:5000])
        elif fmt == 'TAR':
            import tarfile
            with tarfile.open(path) as tf:
                members = tf.getmembers()[:5000]
                try:
                    tf.extractall(out_dir, members=members, filter='data')
                except TypeError:
                    tf.extractall(out_dir, members=members)
        elif fmt == 'GZIP_SINGLE':
            import gzip, shutil as sh
            inner = os.path.join(out_dir, os.path.basename(path)[:-3] or 'gunzipped')
            with gzip.open(path, 'rb') as fi, open(inner, 'wb') as fo:
                sh.copyfileobj(fi, fo, 1 << 20)
        elif fmt == 'XZ_STREAM':
            import lzma, shutil as sh
            inner = os.path.join(out_dir, os.path.basename(path)[:-3] or 'unxzed')
            with lzma.open(path, 'rb') as fi, open(inner, 'wb') as fo:
                sh.copyfileobj(fi, fo, 1 << 20)
        elif fmt == 'SQUASHFS':
            r = subprocess.run(['unsquashfs', '-d', out_dir, path],
                               capture_output=True, timeout=180)
            if r.returncode != 0:
                r = subprocess.run(['sasquatch', '-d', out_dir, path],
                                   capture_output=True, timeout=180)
        elif fmt == 'PYINSTALLER':
            tool = os.path.expanduser('~/tools/pyinstxtractor.py')
            if os.path.exists(tool):
                r = subprocess.run(['python3', tool, path], cwd=out_dir,
                                   capture_output=True, timeout=180)
    except Exception:
        pass
    for dirpath, _, files in os.walk(out_dir):
        for fn in files[:500]:
            children.append(os.path.join(dirpath, fn))
    return children[:2000]

# ---------- stage 0.4: capstone trial-lift ----------

def trial_lift(path):
    if capstone is None:
        return None
    size = os.path.getsize(path)
    if size < 256:
        return None
    with open(path, 'rb') as f:
        f.seek(min(4096, max(0, size // 2)))
        sample = f.read(4096)
    if not sample:
        return None
    printable = sum(1 for b in sample if b in b'\t\n\r' or 32 <= b < 127 or b >= 128)
    if printable / len(sample) > 0.85:
        return {'text': True, 'printable_ratio': round(printable / len(sample), 3)}
    engines = []
    for arch, mode in ((capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                       (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                       (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
                       (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
                       (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
                       (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64)):
        try:
            md = capstone.Cs(arch, mode)
            md.detail = False
            consumed = 0; valid = 0; traps = 0
            gen = md.disasm(sample, 0)
            for ins in gen:
                consumed += ins.size
                valid += 1
                if ins.mnemonic in ('ud2', 'udf', 'break', 'ill', 'unimp'):
                    traps += 1
            if valid < 8:
                continue
            density = consumed / len(sample)
            score = density * (valid / max(consumed, 1)) * 100
            score *= (1 - min(traps / valid, 0.5))
            engines.append({'arch': f"{arch}/{mode}", 'score': round(score, 3),
                            'valid': valid, 'density': round(density, 3)})
        except Exception:
            continue
    if not engines:
        return None
    engines.sort(key=lambda e: -e['score'])
    return engines[0]

# ---------- orchestration ----------

def classify_full(path, sha=None, depth=0):
    fmt, detail, conf = classify_header(path)
    ent = shannon_entropy(path)
    arch = detail.get('arch')
    compiler = detail.get('compiler')
    stripped = detail.get('stripped')
    if fmt is None:
        tl = trial_lift(path)
        if tl and tl.get('text'):
            fmt = 'TEXT_PLAIN'
            detail = {'printable_ratio': tl['printable_ratio']}
            conf = 'text-gate'
        elif tl and tl['score'] > 0.35:
            fmt = 'TRIAL_LIFT_' + tl['arch'].split('/')[0].replace('CS_ARCH_', '')
            arch = tl['arch']
            detail = {'trial_lift': tl}
            conf = 'trial-lift'
        else:
            fmt = 'RAW_UNKNOWN'
            detail = {'trial_lift': tl}
    rec = {'format': fmt, 'confidence': conf, 'entropy': ent, 'detail': detail}
    if sha:
        mark(sha, fmt=fmt, arch=arch, compiler=compiler,
             stripped=int(stripped) if stripped is not None else None, entropy=ent)
    # container recursion
    if fmt in EXTRACTABLE or fmt == 'SQUASHFS':
        if depth < MAX_DEPTH:
            out_dir = os.path.join(CARVE, (sha or os.path.basename(path))[:16])
            os.makedirs(out_dir, exist_ok=True)
            kids = extract_children(path, fmt, out_dir)
            rec['children_carved'] = len(kids)
            child_hits = []
            for kid in kids[:200]:
                try:
                    if os.path.getsize(kid) == 0:
                        continue
                    csha = add_to_cache(kid, tags='carve:' + fmt)
                    if csha:
                        child_hits.append(csha[:12])
                except Exception:
                    continue
            rec['children_ingested'] = len(child_hits)
            if sha and child_hits:
                note(sha, 'carrion-ingest',
                     f"{fmt} carved {len(child_hits)} children into CAS")
    return rec

def cmd_one(a):
    rec = classify_full(a.file)
    print(json.dumps(rec, indent=1))

def cmd_sweep(a):
    conn = db_conn()
    rows = conn.execute("SELECT artifact_id, sha256 FROM artifacts WHERE file_format IS NULL OR file_format IN ('UNKNOWN','RAW_UNKNOWN') OR file_format LIKE 'TRIAL_LIFT_%'").fetchall()
    conn.close()
    total = len(rows)
    print('SWEEP_START', total, flush=True)
    done = 0
    from collections import Counter
    hist = Counter()
    for aid, sha in rows:
        p = blob_path(sha)
        if not os.path.exists(p):
            done += 1
            continue
        try:
            signal.alarm(45)
            rec = classify_full(p, sha=sha)
            signal.alarm(0)
        except Exception as e:
            signal.alarm(0)
            rec = {'format': 'ERROR', 'err': str(e)[:100]}
        hist[rec['format']] += 1
        done += 1
        if done % 500 == 0:
            print(f"HEARTBEAT {done}/{total}", flush=True)
            top = ', '.join(f'{k}:{v}' for k, v in hist.most_common(8))
            print('  top:', top, flush=True)
    print('SWEEP_DONE', done, flush=True)
    print(json.dumps(hist.most_common(), indent=1))

def cmd_histogram(a):
    conn = db_conn()
    rows = conn.execute("SELECT file_format, COUNT(*) FROM artifacts GROUP BY file_format ORDER BY 2 DESC").fetchall()
    conn.close()
    cap = {f['format_id']: f['capability'] for f in FORMATS}
    cap_hist = {}
    known = 0
    for fmt, n in rows:
        c = cap.get(fmt, 'UNKNOWN' if fmt in (None, '', 'UNKNOWN', 'RAW_UNKNOWN') else 'UNMAPPED')
        cap_hist[c] = cap_hist.get(c, 0) + n
        if c in ('FULL', 'LIFT', 'EXTRACT', 'STRUCT'):
            known += n
    print('=== FLEET COVERAGE HISTOGRAM (25k CAS) ===')
    for fmt, n in rows:
        print(f"  {str(fmt):28s} {n:6d}")
    print('=== CAPABILITY ROLLUP ===')
    for c, n in sorted(cap_hist.items(), key=lambda x: -x[1]):
        print(f"  {c:10s} {n:6d}")
    total = sum(cap_hist.values())
    print(f"  TOTAL      {total:6d} · classified {known} ({100*known/max(total,1):.1f}%)")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    po = sub.add_parser('one'); po.add_argument('file'); po.set_defaults(f=cmd_one)
    ps = sub.add_parser('sweep'); ps.set_defaults(f=cmd_sweep)
    ph = sub.add_parser('histogram'); ph.set_defaults(f=cmd_histogram)
    a = p.parse_args()
    a.f(a)

if __name__ == '__main__':
    main()

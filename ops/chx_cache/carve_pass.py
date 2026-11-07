#!/usr/bin/env python3
"""carve_pass.py — Milestone B.3: entropy-bucketed carve of RAW_UNKNOWN CAS blobs.
buckets: entropy >= 7.2 HIGH -> binwalk carve, children re-enter Stage-0 + CAS.
         entropy <  5.0 LOW  -> strings sweep + pointer-density recon (verdict only).
middle band: left dark on purpose (ambiguous, not worth burning cycles).
"""
import sys, os, re, time, json, sqlite3, argparse, subprocess

ROOT = os.path.expanduser('~/carrion_cache')
DB = os.path.join(ROOT, 'index.db')
BLOBS = os.path.join(ROOT, 'blobs')
CARVE = os.path.expanduser('~/carrion_carve/unknown')

def conn():
    c = sqlite3.connect(DB)
    c.execute('PRAGMA journal_mode=WAL;')
    return c

def blob_path(sha):
    return os.path.join(BLOBS, sha[:2], sha)

def ascii_strings(path, minlen=6, cap=200):
    pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
    out = []
    try:
        with open(path, 'rb') as f:
            buf = f.read(2 * 1024 * 1024)
        for m in pat.finditer(buf):
            out.append(m.group().decode('latin1'))
            if len(out) >= cap:
                break
    except Exception:
        pass
    return out

def pointer_density(path):
    """Fraction of 4-byte-aligned LE words that look like userspace pointers."""
    import struct
    try:
        with open(path, 'rb') as f:
            buf = f.read(256 * 1024)
    except Exception:
        return 0.0
    if len(buf) < 64:
        return 0.0
    n = 0; hits = 0
    for off in range(0, len(buf) - 4, 4):
        v = struct.unpack('<I', buf[off:off + 4])[0]
        if 0x1000 <= v <= 0x7FFF0000 or 0x100000000 <= v <= 0x7FFFFF000000:
            hits += 1
        n += 1
    return round(hits / max(n, 1), 3)

MAGIC_PROBES = [
    # (format_hint, bytes)
    ('ELF', b'\x7fELF'), ('PE32', b'MZ'), ('ZIP', b'PK\x03\x04'), ('GZIP', b'\x1f\x8b'),
    ('XZ', b'\xfd7zXZ\x00'), ('SQUASHFS', b'hsqs'), ('SQUASHFS', b'sqsh'),
    ('CPIO', b'070701'), ('DEX', b'dex\n'), ('WASM', b'\x00asm'),
    ('BZIP2', b'BZh'), ('LZ4', b'\x02!L\x18'), ('ZSTD', b'\x28\xb5\x2f\xfd'),
    ('RAR', b'Rar!\x1a\x07'), ('7Z', b'7z\xbc\xaf\x27\x1c'),
    ('OLE', b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'), ('TAR_USTAR', b'ustar'),
    ('PYC', b'\x42\x0d\x0d\x0a'), ('PNG', b'\x89PNG'), ('JPG', b'\xff\xd8\xff'),
    ('PDF', b'%PDF-'), ('SFX_7Z', b'7z\xbc\xaf'), ('OAT', b'oat\n'),
    ('DTB', b'\xd0\x0d\xfe\xed'), ('UBOOT', b'\x27\x05\x19\x56'),
]

def magic_sweep(path, out_base, max_hits=20, max_slice=64 * 1024 * 1024):
    """Scan blob for embedded magics; slice from each hit; return child paths."""
    children = []
    size = os.path.getsize(path)
    try:
        with open(path, 'rb') as f:
            buf = f.read(min(size, 256 * 1024 * 1024))
    except Exception:
        return children
    seen = set()
    hits = 0
    for hint, magic in MAGIC_PROBES:
        start = 0
        while hits < max_hits:
            idx = buf.find(magic, start)
            if idx < 0:
                break
            if hint == 'TAR_USTAR':
                if idx < 257:
                    start = idx + 1; continue
            key = idx // 512
            if key not in seen:
                seen.add(key)
                hits += 1
                end = min(size, idx + max_slice)
                child = os.path.join(out_base, f"{hint.lower()}_{idx:x}.bin")
                try:
                    with open(child, 'wb') as fo:
                        fo.write(buf[idx:end])
                    children.append(child)
                except Exception:
                    pass
            start = idx + 1
        if hits >= max_hits:
            break
    return children

def carve_embedded(path, out_base):
    return magic_sweep(path, out_base)

def add_to_cache(path, tags):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    sha = h.hexdigest()
    try:
        subprocess.run(['python3', os.path.join(ROOT, 'chx_cache.py'), 'add', path, '--tags', tags],
                       capture_output=True, timeout=120)
    except Exception:
        pass
    return sha

def note(c, artifact_id, seat, summary):
    c.execute("INSERT INTO verdicts(artifact_id,analyst_seat,summary,created_at) VALUES(?,?,?,?)",
              (artifact_id, seat, summary, time.time()))
    c.commit()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=None)
    a = ap.parse_args()
    sys.path.insert(0, ROOT)
    from carrion_ingest import classify_full, shannon_entropy
    c = conn()
    rows = c.execute("SELECT artifact_id, sha256, entropy, file_size FROM artifacts WHERE file_format='RAW_UNKNOWN'").fetchall()
    print('CARVE_START unknowns=', len(rows), flush=True)
    from collections import Counter
    stats = Counter()
    done = 0
    for aid, sha, ent, size in rows:
        if a.limit and done >= a.limit:
            break
        p = blob_path(sha)
        if not os.path.exists(p):
            done += 1; continue
        if ent is None:
            ent = shannon_entropy(p) or 0.0
            c.execute("UPDATE artifacts SET entropy=? WHERE artifact_id=?", (ent, aid)); c.commit()
        if ent >= 7.2:
            out_base = os.path.join(CARVE, sha[:12])
            os.makedirs(out_base, exist_ok=True)
            kids = carve_embedded(p, out_base)
            ingested = 0
            for kid in kids:
                try:
                    if os.path.getsize(kid) < 16: continue
                    ksha = add_to_cache(kid, 'carve:unknown')
                    rec = classify_full(kid, sha=ksha)
                    ingested += 1
                except Exception:
                    continue
            stats['HIGH_carved'] += 1
            stats['children'] += ingested
            note(c, aid, 'carrion-carve', f"entropy {ent} >=7.2 -> magic-sweep carved {ingested} children (reclassified)")
        elif ent < 5.0:
            strs = ascii_strings(p)
            pd = pointer_density(p)
            stats['LOW_recon'] += 1
            head = '; '.join(strs[:8])
            note(c, aid, 'carrion-carve',
                 f"entropy {ent} <5.0 -> strings={len(strs)} ptr_density={pd} | {head[:400]}")
        else:
            stats['mid_skipped'] += 1
        done += 1
        if done % 200 == 0:
            print(f"HEARTBEAT {done}/{len(rows)} {dict(stats)}", flush=True)
    print('CARVE_DONE', done, dict(stats))
    total = c.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
    print('artifacts_total_now', total)

if __name__ == '__main__':
    main()

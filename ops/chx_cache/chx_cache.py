#!/usr/bin/env python3
"""chx_cache.py — CarrionHex Storage Bridge v2 (CAS vault host).
Content-addressed artifact store + symbol/verdict index. WAL on.
Doctrine: never analyze the same library twice. Stdlib only (blake3 optional).

usage:
  chx_cache.py add <file> [--tags a,b]      # ingest artifact (dedup by sha256)
  chx_cache.py has <file>                   # hash file, exit 0 known / 1 new
  chx_cache.py has --hash <sha256>          # direct hash query (G2 contract)
  chx_cache.py query <sha256|name>          # artifact or symbol lookup
  chx_cache.py note <file|sha> <seat> <verdict...>   # attach lane verdict (v2)
  chx_cache.py stats                        # counters
"""
import sys, os, sqlite3, hashlib, shutil, time, argparse

ROOT = os.path.expanduser('~/carrion_cache')
DB = os.path.join(ROOT, 'index.db')
BLOBS = os.path.join(ROOT, 'blobs')
MAX_INLINE = 512 * 1024 * 1024

try:
    import blake3 as _b3
    def b3_of(path):
        h = _b3.blake3()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
except Exception:
    def b3_of(path):
        return None

SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts(
 artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
 sha256 TEXT UNIQUE NOT NULL, blake3 TEXT UNIQUE,
 file_name TEXT, file_size INTEGER, file_format TEXT, arch TEXT,
 compiler TEXT, entropy REAL, is_stripped INTEGER DEFAULT 0,
 first_seen REAL, last_accessed REAL,
 paths TEXT, tags TEXT, ext TEXT);
CREATE TABLE IF NOT EXISTS symbols(
 artifact_sha TEXT, name TEXT, kind TEXT, addr TEXT,
 PRIMARY KEY(artifact_sha, name, addr));
CREATE TABLE IF NOT EXISTS functions(
 function_id INTEGER PRIMARY KEY AUTOINCREMENT,
 artifact_id INTEGER, entry_point_va TEXT, cfg_hash TEXT,
 mangled_name TEXT, demangled_name TEXT, inferred_name TEXT,
 confidence REAL DEFAULT 0.0, prototype TEXT, ast_json_hash TEXT,
 FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS recovered_types(
 type_id INTEGER PRIMARY KEY AUTOINCREMENT,
 artifact_id INTEGER, type_name TEXT, type_definition TEXT,
 size_bytes INTEGER, verified INTEGER DEFAULT 0,
 FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS verdicts(
 verdict_id INTEGER PRIMARY KEY AUTOINCREMENT,
 artifact_id INTEGER, analyst_seat TEXT, summary TEXT,
 attack_surface_score REAL, has_memory_safety_issues INTEGER DEFAULT 0,
 created_at REAL,
 FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id));
CREATE INDEX IF NOT EXISTS idx_symbols_name ON symbols(name);
CREATE INDEX IF NOT EXISTS idx_func_cfg ON functions(cfg_hash);
CREATE INDEX IF NOT EXISTS idx_func_name ON functions(inferred_name);
CREATE INDEX IF NOT EXISTS idx_verdicts_aid ON verdicts(artifact_id);
"""

def db():
    os.makedirs(ROOT, exist_ok=True)
    os.makedirs(BLOBS, exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA synchronous=NORMAL;')
    conn.executescript(SCHEMA)
    return conn

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def blob_path(sha):
    return os.path.join(BLOBS, sha[:2], sha)

def cmd_add(a):
    path = os.path.abspath(a.file)
    size = os.path.getsize(path)
    if size > MAX_INLINE:
        print(f"SKIP too big: {size}")
        return 2
    sha = sha256_of(path)
    conn = db()
    row = conn.execute("SELECT paths FROM artifacts WHERE sha256=?", (sha,)).fetchone()
    tags = a.tags or ''
    ext = os.path.splitext(path)[1].lower()
    now = time.time()
    if row:
        paths = row[0] or ''
        if path not in paths.split('|'):
            paths = (paths + '|' + path).strip('|')
        conn.execute("UPDATE artifacts SET last_accessed=?, paths=?, tags=CASE WHEN ?='' THEN tags ELSE ? END WHERE sha256=?",
                     (now, paths, tags, tags, sha))
        conn.commit()
        print(f"KNOWN {sha[:16]} (new path noted)")
        return 0
    dst = blob_path(sha)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(path, dst)
    b3 = b3_of(path)
    conn.execute("INSERT INTO artifacts(sha256,blake3,file_name,file_size,first_seen,last_accessed,paths,tags,ext) VALUES(?,?,?,?,?,?,?,?,?)",
                 (sha, b3, os.path.basename(path), size, now, now, path, tags, ext))
    conn.commit()
    print(f"NEW {sha[:16]} ingested ({size}B)" + (" blake3" if b3 else ""))
    return 0

def cmd_has(a):
    conn = db()
    if a.hash:
        row = conn.execute("SELECT artifact_id FROM artifacts WHERE sha256=?", (a.hash,)).fetchone()
        if row:
            print(f"HIT {a.hash}")
            return 0
        print(f"MISS {a.hash}")
        return 1
    sha = sha256_of(os.path.abspath(a.file))
    row = conn.execute("SELECT artifact_id FROM artifacts WHERE sha256=?", (sha,)).fetchone()
    if row:
        print(f"HIT {sha}")
        return 0
    print(f"MISS {sha}")
    return 1

def cmd_query(a):
    conn = db()
    key = a.key
    if len(key) == 64 and all(c in '0123456789abcdef' for c in key.lower()):
        row = conn.execute("SELECT sha256,file_name,file_size,first_seen,paths,tags,file_format,arch FROM artifacts WHERE sha256=?", (key,)).fetchone()
        print(dict(zip(['sha256', 'file_name', 'file_size', 'first_seen', 'paths', 'tags', 'file_format', 'arch'], row)) if row else "not found")
        return
    rows = conn.execute("SELECT artifact_sha,name,kind,addr FROM symbols WHERE name LIKE ? LIMIT 20", ('%' + key + '%',)).fetchall()
    for r in rows:
        print(dict(zip(['artifact_sha', 'name', 'kind', 'addr'], r)))
    if not rows:
        print("no symbol hits")

def cmd_note(a):
    conn = db()
    sha = None
    if os.path.exists(a.file):
        sha = sha256_of(os.path.abspath(a.file))
    elif len(a.file) == 64:
        sha = a.file
    else:
        print("note needs a file path or sha256")
        return 2
    aid = conn.execute("SELECT artifact_id FROM artifacts WHERE sha256=?", (sha,)).fetchone()
    conn.execute("INSERT INTO verdicts(artifact_id,analyst_seat,summary,created_at) VALUES(?,?,?,?)",
                 (aid[0] if aid else None, a.seat, ' '.join(a.verdict), time.time()))
    conn.commit()
    print(f"noted on {sha[:16]} [{a.seat}]")

def cmd_stats(a):
    conn = db()
    arts = conn.execute("SELECT COUNT(*), COALESCE(SUM(file_size),0) FROM artifacts").fetchone()
    syms = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
    fns = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    types = conn.execute("SELECT COUNT(*) FROM recovered_types").fetchone()[0]
    verd = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
    print(f"artifacts: {arts[0]} ({arts[1]/1e6:.1f} MB) · symbols: {syms} · functions: {fns} · types: {types} · verdicts: {verd}")

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    pa = sub.add_parser('add'); pa.add_argument('file'); pa.add_argument('--tags', default=''); pa.set_defaults(f=cmd_add)
    ph = sub.add_parser('has'); ph.add_argument('file', nargs='?'); ph.add_argument('--hash'); ph.set_defaults(f=cmd_has)
    pq = sub.add_parser('query'); pq.add_argument('key'); pq.set_defaults(f=cmd_query)
    pn = sub.add_parser('note'); pn.add_argument('file'); pn.add_argument('seat'); pn.add_argument('verdict', nargs='+'); pn.set_defaults(f=cmd_note)
    ps = sub.add_parser('stats'); ps.set_defaults(f=cmd_stats)
    a = p.parse_args()
    sys.exit(a.f(a) or 0)

if __name__ == '__main__':
    main()

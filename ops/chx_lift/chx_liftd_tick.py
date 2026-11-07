#!/usr/bin/env python3
# chx_liftd_tick.py — chx-lift0 dumb headless consumer (v0.2)
# Remote python scripts run via stdin heredoc (ssh ["python3","-"]) —
# NEVER via -c with a long string (ssh argv join eats the quoting).
import subprocess, sys, os, json, shutil

import os as _os
_CAS_HOST = _os.environ.get("CHX_CAS_HOST", "cas@YOUR-CAS-HOST")          # ssh alias or user@host
_CAS_DIR  = _os.environ.get("CHX_CAS_DIR",  "/opt/carrion_cache")          # CAS root on the vault
_KEY      = _os.environ.get("CHX_SSH_KEY",  os.path.expanduser("~/.ssh/id_ed25519"))
GATE = ["ssh", "-i", _KEY, "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new", _CAS_HOST]
SCP_BASE = ["scp", "-i", _KEY, "-o", "BatchMode=yes", "-q"]
CAS = _CAS_DIR
WORK = "/work"
GS = "/opt/ghidra"
SCRIPTS = "/opt/ghidra_scripts"

PICK_SRC = """import sqlite3, sys, os, json
c = sqlite3.connect(os.path.join(CAS, "index.db"))
row = c.execute(\"\"\"
SELECT a.artifact_id, a.sha256, a.file_format
FROM artifacts a
WHERE a.file_format IN ('ELF','PE32','MACHO')
  AND EXISTS (SELECT 1 FROM functions f WHERE f.artifact_id = a.artifact_id)
  AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.artifact_id = a.artifact_id AND v.analyst_seat='chx-lift0')
ORDER BY a.artifact_id LIMIT 1\"\"\").fetchone()
if not row:
    print("QUEUE_EMPTY"); sys.exit(0)
aid, sha, fmt = row
blob = os.path.join(CAS, "blobs", sha)
if os.path.isfile(blob):
    src = blob
else:
    p = (c.execute("SELECT paths FROM artifacts WHERE artifact_id=?", (aid,)).fetchone() or [""])[0]
    src = p.split(",")[0].strip() if p else ""
    if not (src and os.path.isfile(src)):
        src = ""
print(json.dumps({"artifact_id": aid, "sha256": sha, "format": fmt, "src": src}))
"""

MARK_SRC = """import sqlite3, json
payload = json.loads('''__PAYLOAD__''')
c = sqlite3.connect(os.path.join(CAS, "index.db"))
c.execute(\"\"\"INSERT INTO verdicts (artifact_id, analyst_seat, summary, created_at)
VALUES (?, 'chx-lift0', ?, datetime('now'))\"\"\", (payload["artifact_id"], payload["summary"]))
c.commit()
print("MARKED")
"""

def remote_mark(mark):
    # payload rides INSIDE the stdin script — ssh argv-join eats spaced args
    src = MARK_SRC.replace("__PAYLOAD__", json.dumps(mark))
    r = subprocess.run(GATE + ["python3", "-"], input=src,
                       capture_output=True, text=True, timeout=120)
    return "MARKED" in (r.stdout or "")

def main():
    os.makedirs(WORK, exist_ok=True)
    # 1. pick candidate
    r = subprocess.run(GATE + ["python3", "-"], input=PICK_SRC,
                       capture_output=True, text=True, timeout=120)
    cand = None
    for line in (r.stdout or "").strip().splitlines():
        if line.startswith("{"):
            cand = json.loads(line)
    if not cand:
        tail = ((r.stderr or "").strip().splitlines() or ["?"])[-1][:160]
        print("TICK_DONE nothing", tail)
        return 0
    aid, sha, fmt = cand["artifact_id"], cand["sha256"], cand["format"]
    src = cand.get("src", "")
    print(f"TICK artifact_id={aid} sha={sha[:12]} fmt={fmt}", flush=True)
    if not src:
        remote_mark({"artifact_id": aid, "summary": "chx-lift0: source bytes unavailable, skipped"})
        print("TICK_DONE no_src marked")
        return 0
    # 2. pull blob
    local_bin = os.path.join(WORK, sha + ".bin")
    r = subprocess.run(SCP_BASE + [f"_CAS_HOST:{src}", local_bin],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not os.path.isfile(local_bin):
        print("PULL_FAIL", (r.stderr or "")[-300:]); return 1
    # 3. headless decompile
    proj = os.path.join(WORK, "proj_" + sha[:16])
    outdir = "/out"
    os.makedirs(proj, exist_ok=True); os.makedirs(outdir, exist_ok=True)
    funcs_out = os.path.join(outdir, "funcs.json")
    if os.path.isfile(funcs_out): os.remove(funcs_out)
    cmd = [os.path.join(GS, "support", "analyzeHeadless"), proj, "p",
           "-import", local_bin,
           "-postScript", "DumpFuncs.java",
           "-scriptPath", SCRIPTS,
           "-deleteProject"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    log_tail = ((r.stdout or "") + (r.stderr or ""))[-400:]
    if not os.path.isfile(funcs_out):
        print("GHIDRA_FAIL", log_tail); return 1
    try:
        nfuncs = len(json.load(open(funcs_out)))
    except Exception:
        nfuncs = -1
    # 4. push JSON back
    remote_dir = CAS + "/decompiled"
    subprocess.run(GATE + ["mkdir", "-p", remote_dir], capture_output=True, timeout=60)
    r = subprocess.run(SCP_BASE + [funcs_out, f"_CAS_HOST:{remote_dir}/{sha}.json"],
                       capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print("PUSH_FAIL", (r.stderr or "")[-300:]); return 1
    # 5. verdict
    ok = remote_mark({"artifact_id": aid,
                      "summary": f"ghidra12.2 decompiled {nfuncs} funcs -> decompiled/{sha}.json"})
    print(f"TICK_DONE aid={aid} funcs={nfuncs} verdict={'OK' if ok else 'FAIL'}")
    shutil.rmtree(proj, ignore_errors=True)
    os.remove(local_bin)
    return 0

if __name__ == "__main__":
    sys.exit(main())

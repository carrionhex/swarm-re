"""Built-in skill kit for SWARM missions.

PE-aware static analysis: strings with hex offsets, section entropy,
imports/exports. Real tools, real evidence, static-only (never executes target).
"""
import subprocess, pathlib, json, re

def _run(cmd, timeout=120, cap=4000):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return {"status": "ok" if p.returncode == 0 else "error",
            "stdout": p.stdout[:cap], "stderr": p.stderr[:2000], "rc": p.returncode}

def _is_pe(target):
    try:
        with open(target, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False

def _section_entropy(path):
    """PE section table via raw structs: name, vaddr, raw offset/size, entropy."""
    import math, struct
    from collections import Counter
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        return []
    peoff = struct.unpack_from("<I", data, 0x3C)[0]
    if data[peoff:peoff+4] != b"PE\x00\x00":
        return []
    nsec = struct.unpack_from("<H", data, peoff+6)[0]
    optsize = struct.unpack_from("<H", data, peoff+20)[0]
    sectab = peoff + 24 + optsize
    secs = []
    for i in range(nsec):
        b = sectab + i*40
        name = data[b:b+8].split(b"\x00")[0].decode("ascii", "replace")
        vsize, vaddr, rawsize, rawoff = struct.unpack_from("<IIII", data, b+8)
        blob = data[rawoff:rawoff+rawsize] if rawsize else b""
        ent = 0.0
        if blob:
            c = Counter(blob)
            n = len(blob)
            ent = -sum((k/n)*math.log2(k/n) for k in c.values())
        secs.append({"name": name, "vaddr": hex(vaddr), "raw_off": hex(rawoff),
                     "raw_size": rawsize, "entropy": round(ent, 2)})
    return secs

def skill_strings(target, mission=None, **kw):
    """strings with hex offsets + diagnostic greps. argv-only: target never
    touches a shell, so hostile filenames cannot inject commands."""
    out = _run(["strings", "-a", "-t", "x", "-n", "6", target], cap=400_000)
    lines = out.get("stdout", "").splitlines()
    out["n_strings"] = len(lines)
    out["interesting_strings"] = [l for l in lines
        if re.search(r"licen|valid|exit|key|serial|regist|trial|version|error|fail", l, re.I)][:40]
    out["strings_head"] = lines[:60]
    return out

def skill_mapper(target, mission=None, **kw):
    """static map: PE-aware. Banks REAL evidence: strings w/ offsets, sections+entropy, imports/exports."""
    if _is_pe(target):
        s = _run(["strings", "-a", "-t", "x", "-n", "6", target], cap=400_000)
        lines = s.get("stdout", "").splitlines()
        secs = _section_entropy(target)
        pe = _run(["objdump", "-p", target], cap=200_000)
        peout = pe.get("stdout", "")
        dlls = re.findall(r"DLL Name: (\S+)", peout)
        interesting = [l for l in lines
            if re.search(r"licen|valid|exit|key|serial|regist|trial|version|error|fail", l, re.I)][:40]
        return {"status": "ok", "format": "PE",
                "size_bytes": pathlib.Path(target).stat().st_size,
                "sections": secs, "import_dlls": dlls[:30],
                "n_strings": len(lines),
                "interesting_strings": interesting,
                "strings_head": lines[:60]}
    # ELF path (argv-only: nm output filtered in python, no shell)
    sym = _run(["nm", "-C", target], cap=200_000)
    symbols = [l for l in sym.get("stdout", "").splitlines()
               if re.search(r"licen|valid|check|verify", l, re.I)][:10]
    res = _run(["objdump", "-d", target], cap=400_000)
    dis = res.get("stdout", "")
    hits = []
    for m in re.finditer(r"call.*<((?:strcmp|memcmp|strlen|check_license|[^>]*licen[^>]*)[^>]*)>", dis):
        start = max(0, m.start() - 600)
        hits.append(dis[start:m.end() + 200])
    return {"status": "ok", "suspect_symbols": symbols[:10],
            "check_sites": hits[:3],
            "n_strcmp_refs": len(re.findall(r"strcmp", dis))}

def skill_tracer(target, mission=None, key="", allow_exec=False, **kw):
    """dynamic: run with a candidate key, observe verdict.

    EXECUTION FIREWALL: the target is only ever executed when the mission
    explicitly allows dynamic analysis (allow_exec=True from the orchestrator
    after parsing the goal). Static missions get a refused stamp, not a run.
    NOTE: no default valid key — a tracer that ships the answer would poison
    the bench. The agent must CANDIDATE the key from static findings, then
    pass it explicitly via key=.
    """
    if not allow_exec:
        return {"status": "refused",
                "reason": "mission is static-only; execution firewall blocked run",
                "target": target}
    # Optional sandbox wrapper: set SWARMRE_SANDBOX to a sandbox launcher
    # installed on the host (e.g. "firejail --quiet", "bwrap --unshare-all
    # --die-with-parent --dev-bind / /"). Dynamic analysis EXECUTES the
    # target — for unknown/malicious samples use a sandbox here and ideally
    # a throwaway VM. See SECURITY.md.
    import os, shlex
    cmd = [target, key]
    wrap = os.environ.get("SWARMRE_SANDBOX", "").strip()
    if wrap:
        cmd = shlex.split(wrap) + cmd
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return {"status": "ok", "output": p.stdout.strip(), "rc": p.returncode,
            "sandbox": wrap or "none"}

def skill_identity(target, mission=None, **kw):
    """FORMAT-AGNOSTIC identity layer (Community MAP mechanical floor).

    Captures, for ANY target (ELF/PE/Mach-O/blob): file verdict, sha256,
    size, ELF header, compiler .comment, full strings census, dynamic imports,
    defined symbols, upx verdict. Everything the free-tier report is allowed
    to cite. Static-only, never executes the target.
    """
    import shutil, hashlib
    p = pathlib.Path(target)
    out = {"status": "ok", "path": str(p)}
    if not p.exists():
        return {"status": "error", "error": f"not found: {target}"}
    data = p.read_bytes()
    out["size_bytes"] = len(data)
    out["sha256"] = hashlib.sha256(data).hexdigest()
    out["file_verdict"] = _run(["file", "-b", target], cap=2000).get("stdout", "").strip()
    out["readelf_h"] = _run(["readelf", "-h", target], cap=4000).get("stdout", "")
    out["comment"] = _run(["readelf", "-p", ".comment", target], cap=3000).get("stdout", "")
    st = _run(["strings", "-a", "-n", "6", target], cap=200_000).get("stdout", "")
    lines = st.splitlines()
    out["n_strings"] = len(lines)
    out["strings_census"] = lines[:250]
    out["dyn_imports"] = _run(["objdump", "-T", target], cap=60_000).get("stdout", "")[:8000]
    out["symbols"] = _run(["nm", "--defined-only", target], cap=60_000).get("stdout", "")[:8000]
    if shutil.which("upx"):
        # real probe: upx -t exits 0 only on a UPX-packed file (4.x)
        _u = subprocess.run(["upx", "-t", target], capture_output=True, text=True, timeout=15)
        out["upx_check"] = ("packed" if _u.returncode == 0 else "not packed") + \
                           " | " + (_u.stdout + _u.stderr).strip()[:200]
    else:
        out["upx_check"] = "upx not installed on this host"
    return out

SKILLKIT = {
    "mapper": skill_mapper,
    "tracer": skill_tracer,
    "strings": skill_strings,
    "identity": skill_identity,
}

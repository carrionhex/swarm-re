#!/usr/bin/env python3
"""chx_enrich.py — Milestone C v0.5: neural symbol enrichment loop.
Pulls mangled names from functions table -> .89 local ollama (qwen2.5vl:7b)
-> inferred_name + confidence on functions rows, verdict row per batch.
This is the CarrionHex neural layer; Dell 7090 lane swaps the endpoint later.

v0.5 (2026-11-07): SHAPE D discovered — model emits an array where ONLY the
  first element keeps its opening brace; the rest are bare "sym": {...}},
  lines. Strict json.loads dies at the closing bracket ("Expecting ','
  delimiter"). Fix: salvage_pairs() regex-scans "sym": {flat} pairs whenever
  extract_json fails (values never nest braces, so [^{}]* is safe). Reached
  ONLY on parse failure — healthy shapes A/B/C path untouched.
v0.4 (2026-11-07): model output drifted across THREE shapes today —
  A: flat object keyed by symbol (morning, original parser worked)
  B: array of single-entry symbol-keyed dicts (mid-day; naive find/rfind
     slice dropped outer brackets -> json.loads failed -> 0/20 all afternoon)
  C: array of positional bare {name,why} with NO symbol keys (evening)
parse_suggestions() handles all three; shape logged per batch for audits.
Also: _DYNAMIC excluded from candidates (ELF section ptr, not a symbol),
ollama timeout 120->240s (CPU ~96s/batch).
"""
import sys, os, re, json, time, sqlite3, argparse, urllib.request

ROOT = os.path.expanduser('~/carrion_cache')
DB = os.path.join(ROOT, 'index.db')
OLLAMA = 'http://127.0.0.1:11434/api/generate'
MODEL = os.environ.get('CHX_ENRICH_MODEL', 'qwen2.5:7b')
LANE = 'chx-enrich/qwen2.5'
BATCH = 20

PROMPT = """You are a reverse-engineering naming assistant. Given C/C++ mangled symbols, suggest short, meaningful snake_case names. Rules:
- If the mangling decodes clearly (it usually does), derive the name from the decoded signature.
- If uncertain, answer null. NEVER invent grandiose names.
- Respond ONLY with a JSON object mapping each mangled symbol to {"name": "...", "why": "one short clause"} or {"name": null}.

Symbols:
%s"""

def conn():
    c = sqlite3.connect(DB)
    c.execute('PRAGMA journal_mode=WAL;')
    return c

def extract_json(text):
    """Bracket-aware parse: model returns either {sym: {...}} or [{...},{...}]."""
    s = text.strip()
    if s.startswith('```'):
        nl = s.find('\n')
        if nl > 0:
            s = s[nl + 1:]
        if s.rstrip().endswith('```'):
            s = s.rstrip()[:-3]
    for open_b, close_b in (('{', '}'), ('[', ']')):
        i, j = s.find(open_b), s.rfind(close_b)
        if i >= 0 and j > i:
            try:
                return json.loads(s[i:j + 1])
            except Exception:
                continue
    return None

SALVAGE_RE = re.compile(r'"([^"]+)"\s*:\s*(\{[^{}]*\})')

def salvage_pairs(text):
    """Shape D fallback: brace-missing array elements. Values are flat
    {name,why} dicts (never nest braces), so a pair-scan recovers every
    suggestion json.loads can't."""
    out = {}
    for m in SALVAGE_RE.finditer(text):
        sym, inner = m.group(1), m.group(2)
        try:
            v = json.loads(inner)
        except Exception:
            continue
        if isinstance(v, dict) and ('name' in v or 'why' in v):
            out[sym] = v
    return out

def parse_suggestions(text, names):
    """All observed model shapes -> ({mangled: {name, why}}, shape_tag)."""
    parsed = extract_json(text)
    if parsed is None:
        salvaged = salvage_pairs(text)
        if salvaged:
            return salvaged, 'D'
        return None, 'fail'
    out = {}
    shape = '?'
    if isinstance(parsed, dict):
        if 'name' in parsed and not any(isinstance(v, dict) for v in parsed.values()):
            if names:
                out[names[0]] = parsed
            shape = 'A1'
        else:
            for k, v in parsed.items():
                if isinstance(v, dict):
                    out[k] = v
            shape = 'A'
    elif isinstance(parsed, list):
        keyed = {}
        positional = []
        for item in parsed:
            if isinstance(item, dict):
                if 'name' in item:
                    positional.append(item)
                else:
                    for k, v in item.items():
                        if isinstance(v, dict):
                            keyed[k] = v
        if keyed:
            out.update(keyed)
            shape = 'B'
        elif positional:
            for nm, sug in zip(names, positional):
                out[nm] = sug
            shape = 'C'
    return out, shape

def ollama_rename(names, timeout=240):
    payload = {"model": MODEL, "prompt": PROMPT % '\n'.join(names),
               "stream": False, "options": {"temperature": 0}}
    req = urllib.request.Request(OLLAMA, data=json.dumps(payload).encode(),
                                 headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read().decode())
    text = body.get('response', '')
    sug, shape = parse_suggestions(text, names)
    if sug is None:
        print('parse_fail', text[:120].replace('\n', ' '), flush=True)
        return {}, shape
    return sug, shape

def note(c, artifact_id, summary):
    c.execute("INSERT INTO verdicts(artifact_id,analyst_seat,summary,created_at) VALUES(?,?,?,?)",
              (artifact_id, LANE, summary, time.time()))
    c.commit()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--limit', type=int, default=100)
    a = ap.parse_args()
    c = conn()
    rows = c.execute("""SELECT f.function_id, f.artifact_id, f.mangled_name FROM functions f
                        WHERE f.mangled_name IS NOT NULL AND f.mangled_name != ''
                          AND (f.inferred_name IS NULL OR f.inferred_name = '')
                          AND f.mangled_name NOT LIKE '.%'
                          AND f.mangled_name != '_DYNAMIC'
                          AND (substr(f.mangled_name,1,2) = '_Z'
                               OR substr(f.mangled_name,1,1) = '?'
                               OR substr(f.mangled_name,1,2) = '_D')
                        LIMIT ?""", (a.limit,)).fetchall()
    print(f"ENRICH candidates: {len(rows)}", flush=True)
    renamed = batches = errs = 0
    for i in range(0, len(rows), BATCH):
        chunk = rows[i:i + BATCH]
        names = [r[2] for r in chunk]
        try:
            sug, shape = ollama_rename(names)
        except Exception as e:
            print('ollama_err', str(e)[:100], flush=True)
            errs += 1
            continue
        applied = 0
        for fid, aid, mangled in chunk:
            s = sug.get(mangled)
            if s and s.get('name'):
                c.execute("UPDATE functions SET inferred_name=?, confidence=? WHERE function_id=?",
                          (s['name'][:128], 0.7, fid))
                applied += 1
        c.commit()
        for fid, aid, mangled in chunk[:1]:
            note(c, aid, f"neural rename batch: {applied}/{len(chunk)} inferred via {MODEL}")
        renamed += applied
        batches += 1
        print(f"batch {batches}: shape={shape} applied {applied}/{len(chunk)} (total {renamed})", flush=True)
    print(f"ENRICH_DONE renamed={renamed} batches={batches} errors={errs}")

if __name__ == '__main__':
    main()

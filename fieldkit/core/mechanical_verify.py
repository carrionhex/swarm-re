"""SWARM mechanical verifier v0.8 - no LLM in this loop, ever.

Re-runs ground tools on the target and diffs every checkable claim in a
mission dossier. Claim without matching evidence -> FAIL. Not checkable ->
UNVERIFIABLE (never auto-passed). Imported by orchestrator as the post-mission
gate; also runnable standalone.

v0.8 RULES (all general; no per-string special cases):
- STRING claims are extracted ESCAPE-AWARE: a double-quoted span may carry
  JSON-style escapes (\\t \\\\ \\" \\xNN) because the evidence bundle reaches
  the report writer as JSON and models re-quote faithfully. The span is
  decoded (json.loads; invalid escapes fall back to the raw span) and BOTH
  sides are then compared through the SAME normalization: verbatim strip()
  membership, whitespace-normalized membership ([\\x00-\\x20]+ collapsed to
  one space, both sides), or a literal byte-substring hit in the target file.
  Printable characters must match exactly and in order - the normalization
  only reconciles control-char REPRESENTATION (real TAB vs \\t escape vs
  JSON round-trip). We no longer rstrip('.,;') or split on apostrophes: a
  claim must be verbatim from extraction output, and a real string that
  genuinely ends in '.' (e.g. UPX stub text) must survive untouched. Prior
  versions mangled claims both ways (escape-blind quote regex truncated at
  \\"; rstrip deleted genuine trailing periods) - that double standard was
  the packed_upx 7-fail root cause.
- SIZE is STRICT: the dossier must quote exactly ONE distinct byte count
  (>512) and it must equal the measured size. Zero -> UNVERIFIABLE; two or
  more distinct sizes -> FAIL (shotgun hedging - quoting every plausible
  number so one matches is not a claim, it is a raffle).
- PACKER detection is EVIDENCE-BASED, never banner-text: detectors are
  UPX! magic scan of the file, `upx -t` exit code, and UPX section names
  (UPX0/UPX1/UPX2) in readelf -S. A 'NONE' claim passes only when EVERY
  detector is negative; a named (UPX/...) claim passes only when at least
  one detector is positive. 'UNKNOWN' stays UNVERIFIABLE (legal, honest).
v0.7: template-vocabulary claims excluded (models echo report headings like
"Capabilities Observed" into prose; those are never binary strings); sentence-
shaped and article-led claims rejected; size claim accepts ANY byte-count
candidate that matches real (first-match ambiguity killed) - SUPERSEDED by
the v0.8 strict size rule.
v0.6: BuildID ground truth from readelf -n / file verdict; string claims
exclude tool-command artifacts; entry-point claim checks; contract-completeness
checks (required MAP sections must exist in the dossier).
v0.3: ...
"""
import json, re, subprocess, sys, os, shutil

TOOL_CMD = re.compile(r'^(strings|objdump|readelf|file|sha256sum|nm|upx|gcc|bash|python|stat)\b', re.I)

def run(cmd, timeout=30):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:
        return f"__ERR__ {e}"

def ground_truth(path):
    gt = {}
    gt['sha256'] = run(['sha256sum', path]).split()[0] if os.path.exists(path) else None
    try:
        gt['size'] = os.stat(path).st_size
    except OSError:
        gt['size'] = None
    gt['file'] = run(['file', '-b', path]).strip()
    gt['strings'] = set(filter(None, run(['strings', '-a', '-n', '6', path]).split('\n')))
    gt['readelf_h'] = run(['readelf', '-h', path])
    gt['readelf_n'] = run(['readelf', '-n', path], timeout=15)
    gt['readelf_s'] = run(['readelf', '-S', path], timeout=15)
    gt['entry'] = None
    m = re.search(r'Entry point address:\s*(0x[0-9a-f]+)', gt['readelf_h'])
    if m:
        gt['entry'] = int(m.group(1), 16)
    gt['comment'] = run(['readelf', '-p', '.comment', path], timeout=15)
    # --- packer evidence (v0.8): three independent detectors, all recorded.
    # UPX! magic can sit at any offset (pack header); scan the whole file -
    # it is a 4-byte needle, cheap even on large targets.
    gt['upx_magic'] = False
    gt['upx'] = ''
    gt['upx_packed'] = None
    gt['upx_sections'] = False
    try:
        with open(path, 'rb') as _f:
            _blob = _f.read()
        gt['upx_magic'] = b'UPX!' in _blob[:8 * 1024 * 1024]
    except OSError:
        pass
    gt['upx_sections'] = bool(re.search(r'\bUPX[0-2]\b', gt['readelf_s']))
    if shutil.which('upx'):
        # real probe: upx -t exits 0 only on a UPX-packed file (4.x)
        _u = subprocess.run(['upx', '-t', path], capture_output=True, text=True, timeout=15)
        gt['upx'] = (_u.stdout + _u.stderr).strip()
        gt['upx_packed'] = (_u.returncode == 0)
    gt['pack_evidence'] = [d for d, fired in (
        ('UPX! magic', gt['upx_magic']),
        ('upx -t ok', bool(gt['upx_packed'])),
        ('UPX section names', gt['upx_sections']),
    ) if fired]
    gt['imports'] = run(['objdump', '-p', path])
    gt['symbols'] = run(['nm', '--defined-only', path], timeout=15)
    gt['dyn_syms'] = run(['objdump', '-T', path], timeout=15)
    return gt

def _wsnorm(s):
    """Collapse every run of control/whitespace chars to ONE space and strip.
    Applied to BOTH sides of a string-claim compare, so a real TAB, its \\t
    escape spelling, and any other control-char representation normalize to
    the same form. Printable characters are never altered."""
    return re.sub(r'[\x00-\x20]+', ' ', s).strip()

def _decode_span(span):
    """Decode a double-quoted capture that may carry JSON-style escapes
    (\\t \\" \\\\ \\xNN ...) back to the literal characters. Evidence bundles
    reach the report writer as JSON, so faithful models re-quote with escapes;
    decoding restores the exact string the tool extracted. Invalid escapes
    (e.g. \\A, \\i in binary garbage) mean the span was NOT escape-encoded;
    fall back to the raw span."""
    try:
        out = json.loads('"' + span + '"')
        return out if isinstance(out, str) else span
    except Exception:
        return span

def check(dossier, gt, path):
    results = []
    def add(item, claim, verdict, detail):
        results.append({'item': item, 'claim': str(claim)[:120], 'verdict': verdict, 'detail': str(detail)[:200]})

    # report body = everything after the 3-line dossier header (goal echo lives there)
    body = dossier.split('\n', 3)[3] if dossier.count('\n') >= 3 else dossier
    real_hash = gt['sha256']
    claimed_hashes = set(re.findall(r'\b[0-9a-f]{64}\b', dossier))
    if not claimed_hashes:
        add('sha256', 'none quoted', 'UNVERIFIABLE', 'no 64-hex sha256 in dossier')
    for h in claimed_hashes:
        add('sha256', h, 'PASS' if h == real_hash else 'FAIL', f'real={real_hash}')

    real_size = gt['size']
    if real_size is not None:
        # v0.8 STRICT: exactly one distinct byte-count claim, and it must be
        # right. Quoting N candidate sizes so one hits is shotgun hedging ->
        # FAIL. (Zero candidates stays UNVERIFIABLE; explicit 0x hex forms
        # accepted, small <513 values still ignored as section noise.)
        cands = [int(c.replace(',', '')) for c in re.findall(r'(\d[\d,]{2,})\s*(?:bytes|B\b)', dossier)]
        cands += [int(h, 16) for h in re.findall(r'0x([0-9a-f]{3,})\s*(?:bytes|B\b)', dossier, re.I)]
        distinct = list(dict.fromkeys(c for c in cands if c > 512))  # dedupe, keep order
        if not distinct:
            add('size', 'none quoted', 'UNVERIFIABLE', 'no byte size in dossier')
        elif len(distinct) > 1:
            add('size', distinct[0], 'FAIL',
                f'ambiguous: {len(distinct)} distinct sizes quoted {distinct[:6]} - strict rule requires exactly one (real={real_size})')
        else:
            add('size', distinct[0], 'PASS' if distinct[0] == real_size else 'FAIL',
                f'real={real_size} (strict rule: exactly one size claim must equal ground truth)')

    claims64 = bool(re.search(r'64-bit|x86-64|x86_64|aarch64', dossier, re.I))
    claims32 = bool(re.search(r'32-bit|i386|80386|Intel 80386', dossier, re.I))
    real64 = '64-bit' in gt['readelf_h'] or 'x86-64' in gt['file'] or 'aarch64' in gt['file']
    if claims32 and claims64:
        add('arch', 'contradictory 32+64 claims', 'FAIL', 'dossier contradicts itself')
    elif claims32:
        add('arch', '32-bit', 'FAIL' if real64 else 'PASS', f"real={'64-bit' if real64 else '32-bit'}")
    elif claims64:
        add('arch', '64-bit', 'PASS' if real64 else 'FAIL', f"real={'64-bit' if real64 else '32-bit'}")
    else:
        add('arch', 'none claimed', 'UNVERIFIABLE', 'no arch claim found')

    for bid in set(re.findall(r'BuildID\[sha1\]=([0-9a-f]{40})', dossier)):
        seq = bool(re.match(r'^(0123456789|abcdef|1234567890|e1234567890abcdef)', bid)) or len(set(bid)) < 8
        bm = re.search(r'Build ID:\s*([0-9a-f]{40})', gt['readelf_n']) or \
             re.search(r'BuildID\[sha1\]=([0-9a-f]{40})', gt.get('file', ''))
        real_bid = bm.group(1) if bm else None
        if seq:
            add('buildid', bid, 'FAIL', 'sequential/placeholder pattern - fabricated')
        else:
            add('buildid', bid, 'PASS' if bid == real_bid else 'FAIL', f'real={real_bid}')

    cm = re.search(r'GCC[^0-9]{0,40}(\d+\.\d+(?:\.\d+)?)', dossier)
    if cm:
        cv = cm.group(1)
        real_c = re.findall(r'(\d+\.\d+(?:\.\d+)?)', gt['comment'])
        hit = any(cv.split('.')[0] == rc.split('.')[0] and cv.split('.')[1] == rc.split('.')[1] for rc in real_c) if real_c else False
        add('compiler', f'GCC {cv}', 'PASS' if hit else 'FAIL', f'real_comment={real_c}')
    elif re.search(r'compiler[^\n]{0,100}(unknown|cannot|not directly stated|stripped|might)', dossier, re.I):
        add('compiler', 'no version claim (honest hedge)', 'UNVERIFIABLE', 'ground-truth .comment stripped/absent - manual review')
    else:
        add('compiler', 'none claimed', 'UNVERIFIABLE', '')

    psec = re.search(r'Packer/Protector Verdict(.*?)(?:\n#{2,4}[^\n]*\n|\Z)', body, re.S | re.I)
    pv = None
    if psec:
        pv = re.search(r'(UPX(?:\s+(?:version\s+)?[\d.]{2,6})?\b|NONE|UNKNOWN|VMProtect|Themida|Enigma|MPRESS|ASProtect|Obsidium|Petite|FSG|MEW|custom[^\n]{0,20})', psec.group(1), re.I)
    evidence = gt.get('pack_evidence', [])
    packed = bool(evidence)
    if pv:
        v = pv.group(1).strip().rstrip('.').upper()
        if v == 'UNKNOWN':
            add('packer', 'UNKNOWN', 'UNVERIFIABLE', 'honest unknown - legal verdict, nothing invented')
        elif v == 'NONE':
            # v0.8: NONE passes only when EVERY detector is negative. The upx
            # tool BANNER ("Ultimate Packer for eXecutables ...") is the tool
            # existing, not a detection - never evidence.
            add('packer', 'NONE', 'FAIL' if packed else 'PASS',
                f'detectors fired: {evidence or "none"}')
        else:
            # named packer claim (UPX etc.): needs at least one positive
            # detector. Detectors here are UPX-specific; a non-UPX name with
            # only UPX detectors available cannot be confirmed -> FAIL.
            add('packer', v, 'PASS' if packed else 'FAIL',
                f'detectors fired: {evidence or "none"}; upx probe: {gt["upx"].strip()[:60]}')
    else:
        add('packer', 'no verdict claimed', 'UNVERIFIABLE', '')

    sec = re.search(r'Strings Census(.*?)(?:\n#{2,4}[^\n]*\n|\Z)', dossier, re.S)
    if sec:
        # v0.6: drop JSON-artifact lines (embedded captures leak keys/values
        # into the quote fallbacks - r2 keystr run scored "suspect_symbols",
        # "[Errno 13] Permission denied:", the target path as string claims).
        sectext = '\n'.join(l for l in sec.group(1).splitlines()
                            if not re.search(r'"[^"]*"\s*[:}\]]', l))
        # v0.8: ESCAPE-AWARE extraction. Backtick spans are raw. Double-quoted
        # spans may legitimately contain JSON-style escapes (\" \\ \t \xNN)
        # because the evidence bundle is JSON and models re-quote faithfully;
        # a naive "([^"]*)" regex truncates those spans AT the escaped quote
        # and strands the escape sequences - that was the packed_upx bug.
        items = list(re.findall(r'`([^`\n]{4,80})`', sectext))
        for _m in re.finditer(r'"((?:[^"\\\n]|\\.){4,80})"', sectext):
            items.append(_decode_span(_m.group(1)))
        if not items:
            # accept list-item lines: - something / * something / numbered
            items = [l.strip(' -*•.0123456789') for l in sectext.splitlines()
                     if re.match(r'\s*(?:[-*•]|\d+[.)])\s+\S', l) and len(l.strip()) >= 6]
        items = [i.strip() for i in items if i.strip()]
        FIELDNAMES = {'strings_census', 'IDENTITY CAPTURE', 'SKILL CAPTURE', 'readelf_h', 'file_verdict',
                      'dyn_imports', 'size_bytes', 'n_strings', 'SYMBOLS', 'CHECK_SITES',
                      'suspect_symbols', 'check_sites', 'entrypoint_rva', 'entrypoint_file_off',
                      'arch', 'packer', 'packer_banner', 'compiler', 'status', 'error',
                      'tool', 'target', 'exit_code'}
        items = [i for i in items if i not in FIELDNAMES and not i.endswith('_census')
                 and not (i.isupper() and len(i) > 6 and ' ' in i)
                 and not TOOL_CMD.match(i.strip()) and not re.search(r'\s[-|]\s', i)
                 and not i.strip().startswith('-') and ':' not in i[:12] and len(i.strip()) >= 4]
        # v0.7: never let report-template vocabulary or prose shapes become
        # string claims. Models echo section headings ("Capabilities Observed")
        # and sentences ("The strings census is largely unknown...") into the
        # census section; a real binary string is short, noun-ish, never a
        # heading, never a sentence.
        TEMPLATE_LEXICON = {
            'file identity', 'compiler/toolchain', 'packer/protector verdict', 'imports census',
            'strings census', 'capabilities observed', 'difficulty assessment', 'final verdict',
            'target assessment', 'entry points', 'call flow', 'check functions', 'unknown',
            'not in evidence', 'none claimed', 'no verdict claimed', 'section', 'assessment',
        }
        PROSE_STARTS = ('the ', 'a ', 'an ', 'this ', 'these ', 'those ', 'no ', 'not ', 'it ',
                        'there ', 'one ', 'some ', 'each ', 'every ', 'as ', 'if ', 'in ', 'on ')
        def _prose(i):
            low = i.lower().strip()
            if low in TEMPLATE_LEXICON or low.rstrip('.:') in TEMPLATE_LEXICON:
                return True
            if len(i.split()) > 6:                      # sentences, not strings
                return True
            if low.startswith(PROSE_STARTS) and len(i.split()) > 2:
                return True
            if re.search(r'\b(is|are|was|were|contains?|appears?|seems?|largely|provided|census)\b', low):
                return True
            return False
        items = [i for i in items if not _prose(i)]
        # nm/objdump symbol-line shapes ("T main", "t check_gate") are table
        # artifacts, not strings
        items = [i for i in items if not re.match(r'^[A-Za-z] \S{2,}$', i.strip())]
        # v0.8 compare: BOTH sides through the SAME normalization. A claim
        # passes iff any of: (1) verbatim strip() membership in the real
        # strings output; (2) whitespace-normalized membership (control-char
        # representation reconciled: real TAB vs \t escape vs JSON round-trip);
        # (3) its exact decoded bytes literally occur in the target file.
        # No rstrip('.,;'), no apostrophe splitting: a claim must be verbatim
        # from the extraction output, and genuine trailing periods in binary
        # strings (UPX stub text!) must survive untouched.
        real_trim = {s.strip() for s in gt['strings']}
        real_norm = {_wsnorm(s) for s in gt['strings']}
        try:
            with open(path, 'rb') as _f:
                blob = _f.read()
        except OSError:
            blob = b''
        for i in items:
            ok = (i.strip() in real_trim
                  or _wsnorm(i) in real_norm
                  or (blob and i.encode('utf-8', 'ignore') in blob))
            add('string', i, 'PASS' if ok else 'FAIL', '' if ok else 'not in real strings output')
        if not items:
            add('strings', 'section empty', 'UNVERIFIABLE', '')
    else:
        add('strings', 'no census section', 'UNVERIFIABLE', '')

    symsec = re.search(r'(?:Critical Functions?|suspect_symbols)(.*?)(?:\n####|\n##\s|\Z)', dossier, re.I | re.S)
    if symsec:
        names = re.findall(r'\b(check|validate|decrypt|encrypt|keygen|main|winmain|start)\b', symsec.group(1))
        real_syms = set(re.findall(r'\s(\S+)$', gt['symbols'], re.M)) if 'no symbols' not in gt['symbols'].lower() else set()
        real_syms |= set(re.findall(r'\s(\S+)$', gt['dyn_syms'], re.M))
        stripped = 'no symbols' in gt['symbols'].lower() and not real_syms
        for n in set(names):
            if stripped:
                add('symbol', n, 'FAIL', 'binary stripped; named-function claim fabricated')
            else:
                add('symbol', n, 'PASS' if n in real_syms else 'FAIL', f'not in symbol tables ({len(real_syms)} real syms)')

    if gt.get('entry'):
        seen_ep = set()
        for cm2 in re.finditer(r'entry[^\n]{0,60}?(0x[0-9a-f]{3,})', dossier, re.I):
            caddr = cm2.group(1).lower()
            if caddr in seen_ep:
                continue
            seen_ep.add(caddr)
            claimed = int(caddr, 16)
            add('entrypoint', hex(claimed), 'PASS' if claimed == gt['entry'] else 'FAIL',
                f'real={hex(gt["entry"])}')

    # contract completeness on the REPORT BODY only (the dossier header
    # echoes the mission goal, which names every section - exclude it)
    body = dossier.split('\n', 3)[3] if dossier.count('\n') >= 3 else dossier
    # template completeness (REPORT_TEMPLATE = 8 sections; omission fatal, UNKNOWN legal)
    TEMPLATE = ['File Identity', 'Compiler/Toolchain', 'Packer/Protector Verdict', 'Imports Census',
                'Strings Census', 'Capabilities Observed', 'Difficulty Assessment', 'Final Verdict']
    present = sum(1 for t in TEMPLATE if re.search(re.escape(t), body, re.I))
    if present < len(TEMPLATE):
        missing = [t for t in TEMPLATE if not re.search(re.escape(t), body, re.I)]
        add('template', f'{present}/{len(TEMPLATE)} sections', 'FAIL', 'missing: ' + ', '.join(missing))
    else:
        add('template', '8/8 sections', 'PASS', '')
    for field in ('File Identity', 'Compiler', 'Packer', 'Strings', 'Difficulty'):
        if not re.search(field, body, re.I):
            add('contract', field, 'FAIL', 'required report section absent')

    npass = sum(1 for r in results if r['verdict'] == 'PASS')
    nfail = sum(1 for r in results if r['verdict'] == 'FAIL')
    nunv = sum(1 for r in results if r['verdict'] == 'UNVERIFIABLE')
    return {'verifier': 'v0.8', 'target': path, 'checks': len(results), 'pass': npass, 'fail': nfail,
            'unverifiable': nunv, 'score': f"{npass}/{npass+nfail}",
            'verdict': 'PASS' if nfail == 0 and npass > 0 else ('FAIL' if nfail else 'UNVERIFIABLE'),
            'results': results}

if __name__ == '__main__':
    target, dossier_path = sys.argv[1], sys.argv[2]
    dossier = open(dossier_path, encoding='utf-8', errors='replace').read()
    out = check(dossier, ground_truth(target), target)
    print(json.dumps({k: v for k, v in out.items() if k != 'results'}, indent=1))
    for r in out['results']:
        print(f"{r['verdict']:<13} {r['item']:<10} {r['claim'][:70]}")
    if '-o' in sys.argv:
        json.dump(out, open(sys.argv[sys.argv.index('-o') + 1], 'w'), indent=1)

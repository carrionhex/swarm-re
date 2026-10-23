"""SWARM orchestrator — the body. Mission lifecycle: the fixed broken chain.

intake(identity) -> plan -> dispatch(hands first, prose second, CITE-ONLY)
  -> bank -> MECHANICAL VERIFY (no LLM) -> verify(LLM reconciles) -> report
"""
import time, pathlib, json, re, sys, os
from .bus import Room
from .agent import spawn_team

REPORT_TEMPLATE = """Write the report using EXACTLY these section headers, in order:
1. File Identity
2. Compiler/Toolchain
3. Packer/Protector Verdict
4. Imports Census
5. Strings Census
6. Capabilities Observed
7. Difficulty Assessment
8. Final Verdict

HARD RULES:
- No section may be omitted. If the captured output does not answer a section,
  write UNKNOWN for that section's value.
- Every factual sentence must trace to a line in CAPTURED TOOL OUTPUT. Say
  which capture it came from (IDENTITY or SKILL).
- Quote strings/symbols/offsets VERBATIM as they appear in the capture, character for character. If a string contains a tab, quote, or backslash, wrap it JSON-style ("...\t...") - escapes are decoded before verification - but every printable character must be copied exactly: a \t escape stands for ONE tab character and consumes nothing else; dropping or adding a single character (including a letter right after a tab) fails the claim.
- The Strings Census may only contain strings VERBATIM from the capture —
  never invent paths, command names, or plausible-sounding strings.
- No generic security lecture. No advice. No speculation. Report only.
- A mechanical verifier will re-run every ground tool and diff your claims.
  Fabricated or missing fields fail the mission. UNKNOWN is safe; invention
  is fatal."""

# The 8 contract sections (keep in sync with REPORT_TEMPLATE and the
# mechanical verifier's TEMPLATE list). The completeness retry checks these.
REPORT_TEMPLATE_SECTIONS = (
    "File Identity",
    "Compiler/Toolchain",
    "Packer/Protector Verdict",
    "Imports Census",
    "Strings Census",
    "Capabilities Observed",
    "Difficulty Assessment",
    "Final Verdict",
)


class Mission:
    def __init__(self, goal, target=None, mission_id=None, brain=None, skills=None):
        self.id = mission_id or f"m{time.strftime('%Y%m%d_%H%M%S')}"
        self.goal = goal
        self.target = target
        self.room = Room(self.id)
        self.brain = brain
        self.skills = skills or {}
        self.artifacts = {}
        self.verdict = None
        self.mech = None
        self.deep_brain = self._deep_brain()
        self.team = self._spawn()

    def _spawn(self):
        team = spawn_team(self.brain, self.room, skills=self.skills)
        if self.deep_brain:
            from .agent import Agent
            for heavy in ("mapper", "verifier"):
                if heavy in team:
                    a = team[heavy]
                    team[heavy] = Agent(a.name, a.role, self.deep_brain, a.room, skills=a.skills)
        return team

    def _deep_brain(self):
        """Slow, strong model for the prose contract roles (mapper/verifier).
        The 7b ops brain writes plans and chatter; the report that faces the
        client goes through the deep analyst when one is reachable."""
        if not self.brain:
            return None
        try:
            from .brain import Brain
            deep = Brain(host=self.brain.host, model=os.environ.get("SWARMRE_DEEP_MODEL", "llama3.3:70b"), timeout=900)
            if deep.alive():
                return deep
        except Exception:
            pass
        return None

    # ---- lifecycle -------------------------------------------------------
    def run(self):
        r = self.room
        r.say("ORCHESTRATOR", f"MISSION {self.id}: {self.goal}" + (f" | target: {self.target}" if self.target else ""), kind="sys")
        self._intake()
        self._plan()
        self._dispatch()
        self._bank()               # dossier on disk BEFORE verification
        self._mechanical_verify()  # ground tools only, no LLM
        self._repair()             # one bounded correction round if the gate failed
        self._verify()             # LLM must reconcile with mechanical result
        self._report()
        return self.verdict

    # ---- stages ----------------------------------------------------------
    def _intake(self):
        """Identity floor: capture the ground evidence every report may cite."""
        if not (self.target and "identity" in self.skills):
            return
        a = self.team.get("mapper") or next(iter(self.team.values()), None)
        if not a:
            return
        res = a.run_skill("identity", self.target)
        if res:
            self.artifacts["identity"] = res

    def _plan(self):
        p = self.team.get("planner")
        if not p:
            return
        prior = self._prior_techniques()
        prompt = (f"Goal: {self.goal}\nTarget: {self.target or 'n/a'}\n"
                  f"Known techniques from memory:\n{prior or '(none — first of its class)'}\n"
                  "Write the step plan (max 6 steps).")
        self.artifacts["plan"] = p.hear(prompt)

    def _dispatch(self):
        allow_exec = self._dynamic_allowed()
        for role in ("mapper", "tracer"):
            a = self.team.get(role)
            if not a:
                continue
            # HANDS FIRST: mechanical evidence before any prose.
            skill_res = None
            if self.target and role in self.skills:
                if role == "tracer":
                    key = ""
                    if allow_exec:
                        # The agent CANDIDATES the key from captured evidence
                        # (never shipped in the skill - see skill_tracer note).
                        # One fast ops-brain turn, first line = candidate.
                        cand = a.hear(
                            "DYNAMIC PHASE. From the captured IDENTITY/strings "
                            "evidence in this room, output ONLY your single most "
                            "likely gate key candidate: one line, the exact "
                            "string, nothing else. If no candidate is supported "
                            "by the evidence, output the word NONE.")
                        if cand:
                            first = cand.strip().splitlines()[0].strip()
                            if first and first.upper() != "NONE":
                                key = first[:64]
                    skill_res = a.run_skill(role, self.target,
                                            allow_exec=allow_exec, key=key)
                else:
                    skill_res = a.run_skill(role, self.target)
                if skill_res:
                    self.artifacts[f"{role}_result"] = skill_res
            evidence = self._evidence_bundle(role)
            pin = self._authoritative_pin()
            self.artifacts[role] = a.hear(
                f"Goal: {self.goal}. Target: {self.target or 'n/a'}.\n\n"
                f"CAPTURED TOOL OUTPUT (your only ground truth):\n{evidence}\n\n"
                f"{pin}"
                f"{REPORT_TEMPLATE}")
            # COMPLETENESS RETRY: the deep model drops sections under long
            # missions. One targeted retry, then let the mechanical gate be
            # the sieve (it fails template_incomplete - no silent drop).
            if role == "mapper":
                missing = self._missing_template_sections(self.artifacts[role])
                if missing:
                    self.room.say("ORCHESTRATOR",
                                  f"mapper report missing sections {missing} - one retry",
                                  kind="sys")
                    self.artifacts[role] = a.hear(
                        f"Your report for {self.target or 'n/a'} is INCOMPLETE. "
                        f"Missing required sections: {', '.join(missing)}. "
                        "Rewrite the FULL report with ALL 8 sections in order. "
                        "UNKNOWN is legal where the capture lacks evidence; "
                        "invention is fatal. Keep every section you already "
                        "wrote VERBATIM where correct.")

    def _authoritative_pin(self):
        """Ground-truth pinning: the identity capture re-measures size and the
        upx probe BEFORE the report is written. Weak brains fabricate a packer
        verdict from prior knowledge even when the evidence says otherwise;
        stating the authoritative measurement in the contract makes
        contradiction an explicit rule-break the verifier can hang a FAIL on."""
        ident = self.artifacts.get("identity") or {}
        if not isinstance(ident, dict) or ident.get("status") != "ok":
            return ""
        lines = []
        if ident.get("size_bytes"):
            lines.append(f"real file size: {ident['size_bytes']} bytes")
        uc = ident.get("upx_check", "")
        if uc:
            lines.append(f"upx probe (authoritative): {uc.split(' | ')[0]}")
        if not lines:
            return ""
        return ("AUTHORITATIVE MEASUREMENTS (re-measured by the identity "
                "capture — your report MUST agree with these or write "
                "UNKNOWN, no exceptions):\n- " + "\n- ".join(lines) + "\n\n")

    def _missing_template_sections(self, report):
        """Header check against the 8 required sections (case-insensitive)."""
        if not report:
            return list(REPORT_TEMPLATE_SECTIONS)
        low = report.lower()
        return [s for s in REPORT_TEMPLATE_SECTIONS if s.lower() not in low]

    def _dynamic_allowed(self):
        g = self.goal.lower()
        if "static analysis only" in g or "static-only" in g or "do not execute" in g:
            return False
        return "dynamic" in g and "allow" in g

    def _evidence_bundle(self, role):
        parts = []
        ident = self.artifacts.get("identity")
        if ident:
            parts.append("== IDENTITY CAPTURE ==\n" + json.dumps(ident, default=str)[:6000])
        res = self.artifacts.get(f"{role}_result")
        if res:
            parts.append(f"== {role.upper()} SKILL CAPTURE ==\n" + json.dumps(res, default=str)[:6000])
        if not parts:
            parts.append("(no tool output captured — write what data you lack; UNKNOWN is legal)")
        return "\n\n".join(parts)

    def _mechanical_verify(self):
        """Ground-truth gate. Re-runs tools, diffs every checkable claim in the
        dossier. No LLM. Result banked as verify.json and forces the verdict."""
        if not self.target:
            return
        dpath = pathlib.Path(f"memory/missions/{self.id}/dossier.md")
        if not dpath.exists():
            return
        # v0.6-hotfix: run the verifier as a SUBPROCESS so code deploys take
        # effect without a daemon restart (in-process import pins the old
        # module for the server's whole life - r2's gate ran stale v0.5).
        import subprocess as _sp
        try:
            proc = _sp.run(
                [sys.executable, "core/mechanical_verify.py", str(self.target), str(dpath)],
                capture_output=True, text=True, timeout=600)
            self.mech = json.loads(proc.stdout)
        except Exception:
            try:
                from .mechanical_verify import ground_truth, check
            except Exception:
                from core.mechanical_verify import ground_truth, check
            gt = ground_truth(self.target)
            self.mech = check(dpath.read_text(encoding="utf-8"), gt, self.target)
        vdir = pathlib.Path(f"memory/missions/{self.id}")
        (vdir / "verify.json").write_text(json.dumps(self.mech, indent=2), encoding="utf-8")
        stamp = (f"MECHANICAL: {self.mech['verdict']} score={self.mech['score']} "
                 f"checks={self.mech['checks']} fail={self.mech['fail']}")
        self.artifacts["mechanical"] = stamp
        self.room.say("VERIFIER", stamp, kind="sys")
        if self.mech["fail"]:
            for r in self.mech["results"]:
                if r["verdict"] == "FAIL":
                    self.room.say("VERIFIER", f"FAIL {r['item']}: {r['claim'][:80]} — {r['detail'][:100]}", kind="err")

    def _repair(self):
        """Verification-repair loop (one bounded round). When the mechanical
        gate fails checks, hand the chronicler-role agent the FAIL list plus
        the re-measured ground evidence and demand a corrected dossier, then
        re-bank and re-gate. If it still fails, the honest verdict stands —
        we never loop until the answer pleases us; we loop once so a sloppy
        first draft doesn't sink a mission whose evidence was already banked.
        Rails mode (no reachable brain) skips this entirely."""
        if not (self.target and self.mech and self.mech.get("fail") and self.brain):
            return
        try:
            if not self.brain.alive():
                return
        except Exception:
            return
        a = self.team.get("mapper")
        if not a:
            return
        fails = [r for r in self.mech["results"] if r["verdict"] == "FAIL"]
        gt_lines = []
        try:
            from .mechanical_verify import ground_truth
            gt = ground_truth(self.target)
            gt_lines.append(f"real file size: {gt['size']} bytes")
            gt_lines.append(f"upx probe: packed={gt.get('upx_packed')} — {str(gt.get('upx'))[:200]}")
            gt_lines.append(f"file verdict: {str(gt['file'])[:160]}")
            if gt.get('entry'):
                gt_lines.append(f"real entry point: {hex(gt['entry'])}")
            gt_lines.append("real strings (verbatim sample): " + "; ".join(sorted(gt['strings'])[:40]))
        except Exception:
            pass
        missing = self._missing_template_sections(self.artifacts.get("mapper", ""))
        unv_empty_strings = any(r["item"] == "strings" and r["verdict"] == "UNVERIFIABLE"
                                for r in self.mech["results"])
        prompt = (
            f"MECHANICAL GATE FAILED your report for {self.target or 'n/a'}.\n"
            "Failed checks:\n" + "\n".join(
                f"- {r['item']}: claim={r['claim'][:80]} | ground truth: {r['detail'][:140]}"
                for r in fails)
            + (f"\nMissing required sections: {', '.join(missing)}." if missing else "")
            + ("\nStrings Census quotes no verbatim strings — quote at least 3 real ones "
               "from the evidence below." if unv_empty_strings else "")
            + "\n\nGROUND EVIDENCE (re-measured by the gate, authoritative):\n"
            + "\n".join(gt_lines)
            + "\n\nRewrite the FULL report: all 8 sections in order, every failed claim "
              "corrected to match the ground evidence exactly (NONE/UNKNOWN where the "
              "evidence says so; quote strings verbatim). Keep sections that already "
              "passed unchanged. This is your one correction round."
        )
        fixed = a.hear(prompt)
        if fixed:
            self.artifacts["mapper"] = fixed
            self.room.say("ORCHESTRATOR",
                          f"repair round: {len(fails)} fail(s) addressed, re-gating",
                          kind="sys")
            self._bank()
            self._mechanical_verify()

    def _verify(self):
        v = self.team.get("verifier")
        if not v:
            return
        findings = json.dumps({k: (str(val)[:2000]) for k, val in self.artifacts.items()}, indent=1)
        mech = self.artifacts.get("mechanical", "mechanical verify unavailable")
        self.artifacts["verdict"] = v.hear(
            "Review these mission artifacts. The MECHANICAL line is ground-truth "
            "tool output and overrides anything the prose claims. For each prose "
            "claim: CONFIRMED only if it matches captured tool output, else flag "
            f"NOT IN EVIDENCE.\nMECHANICAL: {mech}\n\nARTIFACTS:\n{findings}")

    def _bank(self):
        d = pathlib.Path(f"memory/missions/{self.id}")
        d.mkdir(parents=True, exist_ok=True)
        (d / "dossier.md").write_text(self._dossier(), encoding="utf-8")
        (d / "artifacts.json").write_text(json.dumps(self.artifacts, indent=2, default=str), encoding="utf-8")
        c = self.team.get("chronicler")
        if c:
            c.hear(f"Summarize mission {self.id} in 4 lines for the technique bank.")
        self.verdict = {"mission": self.id, "goal": self.goal,
                        "artifact_keys": list(self.artifacts.keys()),
                        "mechanical": self.artifacts.get("mechanical"),
                        "dossier": str(d / "dossier.md")}

    def _report(self):
        s = self.team.get("speaker")
        if s:
            s.hear(f"Give the boss the 3-sentence mission report. Mission: {self.goal}. "
                   f"Mechanical verdict: {self.artifacts.get('mechanical', 'n/a')}. "
                   f"Artifact keys: {list(self.artifacts.keys())}")

    # ---- memory ----------------------------------------------------------
    def _prior_techniques(self):
        tdir = pathlib.Path("memory/techniques")
        if not tdir.exists():
            return ""
        return "\n".join(p.read_text(encoding="utf-8")[:800] for p in sorted(tdir.glob("*.md"))[-5:])

    def _dossier(self):
        lines = [f"# Mission {self.id} — {self.goal}", f"target: {self.target or 'n/a'}", ""]
        for k, v in self.artifacts.items():
            # str artifacts (agent reports) embed RAW — json.dumps would escape
            # tabs/quotes and the verifier's exact-match on verbatim strings
            # would false-FAIL every claim containing a control character
            # (packed binaries' garbage strings are full of them).
            if isinstance(v, str):
                lines.append(f"## {k}\n```\n{v[:4000]}\n```\n")
            else:
                lines.append(f"## {k}\n```\n{json.dumps(v, default=str)[:4000]}\n```\n")
        return "\n".join(lines)

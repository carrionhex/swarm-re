# SWARM v2 ARCHITECTURE — the spine

## Design debts that killed v1 (never repeat)
1. **No git.** Every session rebuilt blind. → git is law; nothing is real until committed.
2. **No missions recorded.** The learning loop had no input. → dossier-or-it-didn't-happen.
3. **Tools as scripts, not skills.** 452 files, zero common interface. → one `run()` contract.
4. **Bot that watches itself.** No command path from chat to workers. → I am the command surface.
5. **Everything on one box, undocumented.** → deploy doc + one-command setup.

## Components

### core/orchestrator.py — the nervous system
- Mission lifecycle state machine: `intake → plan → dispatch → collect → verify → bank → report`
- Worker pool: subprocess/SSH workers on bench hosts (a beefier remote box for heavy jobs)
- Queue: SQLite (adopt `02_SWARM/platform/swarm.db` if schema sane) or Redis if needed later
- API: reuse the dashboard contract (`/api/queue`, `/api/run`, `/api/health`) so the old dashboard
  can serve as the web face on day one

### skills/ — the arsenal (wrapped swarm_tools)
- Every skill: `{name, class(static|dynamic|unpack|patch|intel), run(ctx,target) → result}`
- ctx carries: mission id, memory handles, vault handle, brain (Ollama) handle
- skills/ghidra_bridge — headless Ghidra analysis as a callable skill
- skills/intel_feed — jailbreak/CVE monitor output ingested nightly

### memory/ — the learning bank (the organ v1 never had)
- `missions/<id>/` — full dossier: target hash, plan, per-step results, artifacts, verdicts, failures.
  (Field experience proved this pattern: a well-kept mission dossier is worth more than any single result.)
- `techniques/<class>.md` — per protection-class playbooks (packer X → skill Y works; check rhythm Z →
  approach W). Updated after every mission by a bank step that diffs expected vs actual.
- `agents/` — per-agent notes (what each worker type is good/bad at)
- `vault/` — ChromaDB adoption; retrieval at plan time so missions start with relevant memory

### bench/ — legal targets (training ground)
- crackmes.one import harness (difficulty-graded scoring)
- toy_protector/ — our own licensing system we build then break (spec: docs/TOY_PROTECTOR_SPEC.md)
- CTF corpus + scoreboard; bug-bounty targets list (authorized-scope only)

### bot/ — command surface
- Phase 1 (now): the operator chats with me, I run missions via SSH/HTTP to bench hosts. Zero new code.
- Phase 2: Telegram bot wired to the same mission intake (the legacy watchdog gets a real job).

## Brain
- Ollama :11434 on the bench host for agent reasoning (cheap, local, private)
- Heavy reasoning can burst to a bigger remote host over SSH when needed

## Deploy
- Repo lives in workspace (git origin), pushes to a bare remote on the bench host, checked out there
- Dashboard serves API+web from the bench host; I call it over the LAN
- Setup: one script, idempotent, documented in docs/RUNBOOK.md

## What "keeps learning constantly" means, concretely
Every mission ends with a BANK step that writes: (a) the dossier, (b) technique deltas,
(c) vault embeddings of artifacts. Every mission BEGINS with a PLAN step that reads them.
Learning = the loop never skipping. Constant = the loop runs every mission, no exceptions.

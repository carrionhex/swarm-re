# Milestones — the live bench behind the Field Kit

The SWARM-RE Field Kit runs as a live bench 24/7. This log is what the bench
has learned and shipped, newest first. Everything here feeds back into the kit.

## 2026-11-07 — User-journey capture stack + lift-lane + enrich v0.5

- **One-shot demo recorder** (`ops/recorder/`): Xvfb + kiosk Chromium + CDP
  driver + `ffmpeg x11grab`. Smoothstep cursor, real clicks, file injection
  via `DOM.setFileInputFiles` (no native dialog), **fifo-stop** pattern
  (`ffmpeg <> fifo`, `echo q > fifo`) so variable-length runs always get a
  clean moov atom. Used to film the full console journey — landing → open
  console → drop specimen → deploy swarm → live specialist roster → verdict —
  in one uncut 37-second take.
- **CHX-LIFT0 headless lift lane** (`ops/chx_lift/`): Ghidra 12.2 on a WSL2
  seat (Temurin JDK 25 — Ghidra 12.2's true minimum), `DumpFuncs.java`
  postScript emitting pseudo-C as JSON, systemd timer tick. Decompiled output
  lands in the CAS as `<sha256>.json` so a specimen is only ever lifted once.
- **CHX_ENRICH v0.5**: LLM symbol-renaming lane (local 7B vision model)
  with a **shape-drift-tolerant parser** — the model's output shape changed
  four times in one day (flat object → array of single-entry dicts →
  positional bare dicts → brace-damaged array). Strict `json.loads` dies;
  a salvage regex `(\{[^{}]*\})` recovered every batch. Lesson: probe the
  shape before assuming model death.

## 2026-11-06 — MILESTONE A: Storage Bridge + live topology map

- **Storage Bridge** (`ops/chx_cache/`): sha256-addressed content store.
  25,115 unique artifacts ingested from 38,479 corpus files (1.38 GB).
  The law: `has()` before analyze — never dissect the same library twice.
  Verdicts attach to hashes, so findings survive renames, moves, and re-extracts.
- **Live map** — public topology of the bench: portal → orchestrator →
  worker battery → storage bridge → fleet deck, with a real feed (fleet
  pings, session counts, bridge traffic) painting heartbeat dots.
- **Pipeline scar banked**: `find | while read` wedges silently when find
  dies — the while blocks on a ghost pipe. File-list-first, heartbeats,
  per-item timeouts.

## 2026-11-03 — Bench fortress pass

- sshd key-only, UFW default-deny with service-scoped allows, fail2ban,
  temp accounts deleted, out-of-band management password rotated and
  verified in-band (a 92-char password "worked" but the BMC web UI
  silently truncates — always verify the *set* command's output, and
  never confuse "no RMCP route" with "auth failed").

## 2026-11-02 — Site identity fix (the StackProtect lesson)

- Apex was 403-ing behind a host-side WAF gate (StackProtect, origin nginx).
  Chased Cloudflare config for an hour before a direct-to-origin curl
  reproduced the 403 — the header signature (`x-stackprotect-id`) gave it
  away. **Rule: when the origin header isn't CF's, stop touching CF.**
  Full cutover to the tunnel followed.

## 2026-11-01 — R49 ingest lane

- Five repair-education channels ingested into the knowledge vault
  (cards: title, rails, boards, keywords, frames, transcript path).
  House courtesy: venv-isolated, OMP thread-capped, sequential — don't
  load a shared bench.

## 2026-10-28 — Edge cutover + license archaeology

- Site apex + www served through the edge tunnel; one connector
  (twin daemons = twin-lock deafness — systemd is the only legitimate
  parent of listeners).
- Binary Ninja license sat in a drop folder for weeks while audits kept
  reporting "unlicensed" — they read the install dir, not the downloads.
  **Check the drop folder before declaring a seat unlicensed.**

## 2026-10-14 — Evidence-grade key recovery (defensive study)

- Interception-based recovery of a protected application's license
  material using a minimal sideloaded shim, with five silent-kill failure
  modes documented: real-time AV exclusions, loader-lock in `DllMain`,
  CRT startup returning FALSE, ASLR rebase without relocations, and
  `.def` exporting the literal `Name@16` instead of `Name`. The full
  technique notes are in the vault; the takeaways are in `fieldkit/docs/`.

---

Older history lives in git. Each entry here exists because it cost us
something — scars are the curriculum.

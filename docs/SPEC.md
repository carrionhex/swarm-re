# SWARM-RE — Product Specification (doctrine level)

This document defines what SWARM-RE is for, how its agents behave, and what each
tier owes the user. It is the contract the implementation is tested against.
No internals, no mechanics — the spec of behavior.

## 1. Prime directive: truth on screen

Every number, progress bar, and report shown to the user is produced by a real
agent run against a real input. No simulated data in the shipped product. The
panel is a window into the campaign, never a decoration.

Corollary: marketing captures (screenshots, clips) are captured from real runs.

## 2. The specialist roster

Agents are specialists with one job each. The controller routes work between
them and owns the gate logic.

| Role | Job |
|---|---|
| CONTROLLER | Owns the mission. Splits targets, routes parts, decides gates, assembles the final report. |
| INGEST | Intake: identify file type, hash, size, arch, entropy profile. Rejects garbage early. |
| MAP | Structural survey: sections, imports, exports, strings census, compiler/packer/protector fingerprint, capability hints. Produces the Community report. |
| DISSECT (per domain) | Deep work on assigned parts: disassembly reading, decompilation, crypto identification, unpacking, tracing. |
| QUARTERMASTER | Organizes extracted parts (functions, structs, constants, keys) into the shared evidence store with provenance. |
| REPORTER | Assembles human-readable reports per gate: what was found, what it means, what the next wall is, what gear opens it. |
| VERIFIER | Checks every agent claim against ground truth or corroborating evidence before it reaches the user. Nothing unverified ships. |

## 3. Tier behavior

### Community — "the map, free"

Input: any binary or file.
Output: the full recon report —

- file identity (hashes, type, arch, size, entropy)
- compiler + toolchain fingerprint
- packer/protector identification (or "none / not detected")
- imports/exports census and what they imply
- strings summary (interesting clusters surfaced, full census available)
- capabilities observed (crypto, network, persistence, anti-debug hints)
- difficulty assessment: what the user is up against, gate by gate
- verdict: what a deep campaign would target first, and why

The report ends with the question: **want to dive deeper?**
Deep dives run on Pro gears. The map is the product; the map is the funnel.

### Pro — "every gate, solved"

- full dissection campaigns across all gates (unpack, devirtualize, anti-anti,
  key recovery, protocol reversing)
- all tools and tweaks enabled, every adapter wired
- per-gate agent reports: finding → meaning → solution
- final evidence bundle: sha256-stamped, replayable, auditable

## 4. Testing bar

- every shipped agent claim passes VERIFIER against ground truth on a known
  corpus (crackmes, packed samples, self-built binaries with planted answers)
- accuracy is measured, not asserted: corpus item → expected finding → actual
  finding → pass/fail recorded
- a release candidate must clear the corpus with zero false "solved" claims
  and zero missed protectors/packers

## 5. Integrity rules

- authorized targets only: your software, your binaries, your scope
- evidence bundles are immutable once stamped
- an agent that cannot verify a claim must say "unknown", never guess

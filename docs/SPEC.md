# SWARM-RE — Product Specification v2 (doctrine level)

Behavior contract the implementation is tested against. No internals.

## 1. Prime directive: truth on screen

Every number, progress bar, and report shown to the user is produced by a real
agent run against a real input. No simulated data in the shipped product.
Marketing captures come from real runs only.

## 2. The roster — 10 named agents

| Agent | Seat | Job |
|---|---|---|
| Joe | Intake | File identity: hashes, type, arch, platform verdict. Rejects garbage early. |
| Mike | Windows dept | PE / DLL / .NET targets. |
| Rachid | Apple dept | Mach-O, FAT binaries, iOS IPA. |
| Hamza | Linux/Unix dept | ELF and the *nix format zoo. |
| Greg | Cross-format dept | Firmware, blobs, scripts, packed/VM-protected anything. |
| Josh | Crypto & strings | Algorithm identification, key material hunting, strings census. |
| Jesse | Dynamic lab | Tracing, behavioral analysis, sandbox runs (lab only). |
| (name TBD) | Tech Master | The boss agent. Takes the client order, routes by platform, assigns the work order, runs recap + judgement, delivers the verdict. |
| (name TBD) | Quartermaster | Evidence vault: extracted parts organized with provenance, immutable bundles. |
| (name TBD) | Reporter/Verifier | Final reports; scores every agent claim against evidence or ground truth before it reaches the client. |

Department heads receive work from the Tech Master and may spawn specialists
under their department for a mission.

## 3. The engine mesh (differentiator)

Three decompilers analyze every target, headless, simultaneously:

- Ghidra (headless batch) — free, baseline engine
- Binary Ninja (headless API) — commercial, licensed by the user
- IDA (headless idat + IDAPython) — commercial, licensed by the user

All findings flow into one normalized evidence schema (functions, xrefs,
strings, decompilation, disassembly opinions). Agents then run
cross-engine corroboration: where engines disagree on semantics, an agent
adjudicates from quoted evidence. A claim accepted by the mesh carries
engine-attributed consensus; a disputed claim is flagged, never silently
resolved. Without this mesh SWARM-RE is a wrapper. With it, it is its own species.

## 4. Timing and resources

- Every agent run has a wall-clock budget and a resource envelope (CPU quota,
  memory cap) enforced by the runtime.
- Overrun policy: escalate once, then terminate with partial findings stamped
  INCOMPLETE. An agent is never silently late and never runaway.
- Mission-level budget: the Tech Master tracks cumulative spend and reports it
  in the verdict (time per agent, tokens/compute consumed).

## 5. Work-order pipeline (state machine)

ORDER → INTAKE (Joe: identify platform/format)
     → ROUTE (Tech Master → department)
     → ASSIGN (per-agent work order with budgets)
     → EXECUTE (time-boxed, evidence-quoted, cross-mesh where applicable)
     → RECAP (Tech Master assembles per-agent findings)
     → JUDGE (Reporter/Verifier scores against evidence; UNKNOWN is a legal verdict, a guess is not)
     → VERDICT (final client report: findings, confidence, what you're up against, what a deeper campaign would target)

Every transition is logged to the mission evidence bundle.

## 6. Tiers

Community — the full map (Joe + one department + Reporter): identity, compiler
fingerprint, packer/protector verdict, imports, strings, capabilities,
difficulty, what you're up against. Ends with: "want to dive deeper?"

Pro — the full mesh: every gate worked by the complete roster, per-gate
solutions, engine-consensus evidence bundles.

## 7. Testing bar

- Every shipped claim passes the Verifier against ground truth on a known
  corpus. Accuracy is measured claim-by-claim, not asserted.
- Release candidate: zero false "solved", zero missed protectors/packers.

## 8. Integrity rules

- Authorized targets only: your software, your binaries, your scope.
- Evidence bundles are immutable once stamped.
- UNKNOWN is legal; confabulation is a bug.

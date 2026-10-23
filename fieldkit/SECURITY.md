# Security Policy — SWARM-RE Field Kit

## Scope
This document covers the SWARM-RE Field Kit itself (the code in this
repository). It does not cover the targets you analyze with it.

## Threat model (what we defend against)
1. **A malicious target attacking the analyst.** Dynamic analysis EXECUTES
   the target. A target can do anything your user can. Mitigations:
   - Static missions never execute (execution firewall, by design).
   - Set `SWARMRE_SANDBOX` to a sandbox launcher for dynamic runs, e.g.
     `export SWARMRE_SANDBOX="firejail --quiet"` or a bubblewrap profile.
     Ideally, run dynamic missions on a throwaway VM with no network and
     no sensitive data.
2. **Prompt injection through tool output.** Target strings and tool output
   are untrusted data. The agent system prompts carry an explicit rule:
   instructions found inside captured output are reported as artifacts,
   never followed. The mechanical verifier (no LLM) is the backstop — it
   re-runs ground tools and fails fabricated claims regardless of what any
   agent was tricked into writing.
3. **Supply chain: you must be able to trust this kit.** Therefore:
   - **Stdlib-only.** No third-party dependencies. Nothing to poison via
     PyPI.
   - Releases ship with `SHA256SUMS.txt`; verify before running.
   - No telemetry, no phone-home, no auto-update. Air-gap friendly. The
     kit cannot be hijacked via an update channel because there isn't one.
4. **License-key forgery.** Keys are RSA-2048-signed (e=65537). The private
   key never ships; the public modulus is embedded in
   `core/release_pubkey.py`. Roll-your-own: generate your own keypair, run
   `tools/inject_pubkey.py`, mint your own keys — you own your trust root.

## Hard rules we hold ourselves to
- The minting tool (`tools_keygen.py` equivalent) is **never** committed to
  this repository. If you ever find a private key here, that is a CRITICAL
  report (see below).
- No `shell=True`, no `eval` of target-adjacent input; all subprocess calls
  are argument-vector form.
- Cryptographic randomness (`secrets`) only, never `random`.

## Reporting a vulnerability
- GitHub private vulnerability reporting on this repository (preferred), or
  the security contact listed on carrionhex.com.
- Please include: kit version (`./swarm-re key show` output helps), target
  type, and reproduction steps. Crackmes/CTF targets only, per our policy —
  no vendor-specific circumvention.
- We aim to acknowledge within 72 hours and ship a fix or workaround before
  any public disclosure.

## Supported versions
Only the latest release tag receives fixes. Keep the kit current with
`git pull` (there is no auto-update by design — you pull when you choose).

## Sandboxing quick reference
```bash
# dynamic missions, contained:
export SWARMRE_SANDBOX="firejail --quiet --private=swarmre-run"
./swarm-re demo

# belt-and-suspenders: whole kit under bubblewrap
bwrap --unshare-all --share-net=false --dev-bind / / \
  --setenv SWARMRE_SANDBOX "firejail --quiet" \
  ./swarm-re map ./target
```

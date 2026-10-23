#!/usr/bin/env python3
"""Release build step: embed the community-tier public modulus into the kit.

The private key (d) NEVER ships — it lives only in the Lab backend
(carrionhex-dispatch). This tool writes core/release_pubkey.py, which
core/license_key.py imports at verify time. Run once per release:

    python3 tools/inject_pubkey.py keypair_community.json
    python3 tools/inject_pubkey.py --check          # verify the embed

To roll your own keys (air-gapped org, mirror, research lab): generate a
keypair with tools_keygen.py (server-side, keep d offline), inject your own
n_hex, mint keys for your machines. The kit verifies against whatever
modulus is embedded — you own your trust root.
"""
import hashlib, json, pathlib, sys

CORE = pathlib.Path(__file__).resolve().parent.parent / "core"


def embed(n_hex: str, tier: str = "community") -> pathlib.Path:
    n_hex = n_hex.lower().strip()
    assert len(n_hex) == 512 and all(c in "0123456789abcdef" for c in n_hex), \
        "n_hex must be 512 hex chars (2048-bit modulus)"
    digest = hashlib.sha256(bytes.fromhex(n_hex)).hexdigest()[:16]
    out = CORE / "release_pubkey.py"
    out.write_text(
        '"""Embedded at release build by tools/inject_pubkey.py.\n'
        f'RSA-2048 public modulus, {tier} tier. sha256[:16] = {digest}.\n'
        'Regenerate: python3 tools/inject_pubkey.py keypair_<tier>.json\n'
        '"""\n'
        f'N_HEX = "{n_hex}"\n'
        f'TIER = "{tier}"\n')
    return out


def check() -> None:
    src = CORE / "release_pubkey.py"
    if not src.exists():
        sys.exit("release_pubkey.py missing — run: python3 tools/inject_pubkey.py keypair_community.json")
    ns = {}
    exec(src.read_text(), ns)
    n = bytes.fromhex(ns["N_HEX"])
    print(f"embedded modulus ok: tier={ns.get('TIER')} bits={len(n)*8} sha256[:16]={hashlib.sha256(n).hexdigest()[:16]}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--check":
        check()
    elif len(sys.argv) == 2:
        kp = json.load(open(sys.argv[1]))
        out = embed(kp["n_hex"], kp.get("tier", "community"))
        print(f"wrote {out} — guard the matching d_hex; it never ships")
    else:
        print(__doc__)

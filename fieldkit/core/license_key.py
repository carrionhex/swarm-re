#!/usr/bin/env python3
"""CarrionHex Field Kit — community-tier license keys (offline verification).

Design: RSA-2048 (e=65537) signatures, pure-Python (stdlib only — no deps,
no C extension, auditable line-by-line, runs air-gapped).

  raw  = payload[32] || sig[256]        (288 bytes)
  payload:
    [0:8)   magic      b'CHXFK001'
    [8:16)  machine    first-8 of sha256(normalized hostname|user) — binding
    [16]    tier       0x01 community | 0x02 lab (lab sigs never verify against
                      the embedded community pubkey — two keypairs, two trust roots)
    [17:21) expiry     unix-day count, big-endian; 0 = never
    [21:24) flags
  sig = pow(payload, d, n) — big-endian, full 2048-bit

Rendered: base32 (custom no-confusables alphabet), 4-char groups, CHXK1- prefix.
Verify cost: one 2048-bit powmod (~1 ms). Minting happens ONLY in the Lab
backend (carrionhex-dispatch) — the private key never ships.

Threat model (documented in docs/KEYS.md): forgery = factoring 2048-bit RSA,
out of scope for a free tier. Machine binding stops casual key-sharing; a
posted key activates only the machine it was minted for.
"""
from __future__ import annotations
import hashlib, socket, getpass, time

PREFIX = "CHXK1-"
_B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 32 chars: no I, O, 0, 1
_E = 65537
_TIER_COMMUNITY = 0x01
_TIER_LAB = 0x02
_GRACE_DAYS = 7
_SIG_LEN = 256
_PUBKEY: tuple[int, int] | None = None  # (e, n) injected at release build


# ---------- base32 (custom alphabet), fixed-block, zero padding ambiguity ----------
def _b32enc(raw: bytes) -> str:
    out = []
    for i in range(0, len(raw), 5):
        chunk = raw[i:i + 5].ljust(5, b"\x00")
        bits = int.from_bytes(chunk, "big")
        out.append("".join(_B32[(bits >> (35 - 5 * j)) & 31] for j in range(8)))
    return "".join(out)


def _b32dec(s: str) -> bytes:
    pad = (-len(s)) % 8
    s = s + _B32[0] * pad
    out = bytearray()
    for i in range(0, len(s), 8):
        bits = 0
        for ch in s[i:i + 8]:
            bits = (bits << 5) | _B32.index(ch)
        out += bits.to_bytes(5, "big")
    return bytes(out)


# ---------- machine binding ----------
def machine_hash() -> bytes:
    seed = (socket.gethostname().lower().strip() + "|" +
            getpass.getuser().lower().strip()).encode()
    return hashlib.sha256(seed).digest()[:8]


# ---------- render / parse / verify ----------
def render_key(raw: bytes) -> str:
    body = _b32enc(raw)
    return PREFIX + "-".join(body[i:i + 4] for i in range(0, len(body), 4))


def _pubkey() -> tuple[int, int]:
    global _PUBKEY
    if _PUBKEY is None:
        n_hex = ""
        try:
            from .release_pubkey import N_HEX  # embedded at release build
            n_hex = N_HEX
        except ImportError:
            pass
        if not n_hex:
            import os
            n_hex = os.environ.get("CHX_COMMUNITY_N_HEX", "")
        if not n_hex:
            raise RuntimeError("release pubkey not embedded — run tools/inject_pubkey.py")
        _PUBKEY = (_E, int(n_hex, 16))
    return _PUBKEY


def parse_key(key: str) -> dict:
    k = key.strip().upper().replace(" ", "")
    if not k.startswith(PREFIX):
        return {"ok": False, "error": "bad-prefix"}
    raw = _b32dec(k[len(PREFIX):].replace("-", ""))
    if len(raw) < 32 + _SIG_LEN:
        return {"ok": False, "error": "bad-length"}
    payload, sig = raw[:32], raw[32:32 + _SIG_LEN]
    if payload[:8] != b"CHXFK001":
        return {"ok": False, "error": "bad-magic"}
    e, n = _pubkey()
    if pow(int.from_bytes(sig, "big"), e, n) != int.from_bytes(payload, "big"):
        return {"ok": False, "error": "bad-signature"}
    tier = payload[16]
    exp = int.from_bytes(payload[17:21], "big")
    mh = payload[8:16]
    out = {"ok": True, "tier": "community" if tier == _TIER_COMMUNITY else "lab",
           "machine": mh.hex(), "machine_match": hmac_cmp(mh, machine_hash())}
    if exp:
        today = int(time.time()) // 86400
        out["expired"] = today > exp + _GRACE_DAYS
        out["days_left"] = exp - today
    return out


def hmac_cmp(a: bytes, b: bytes) -> bool:
    return hashlib.sha256(a).digest() == hashlib.sha256(b).digest()


def require_active(key: str) -> dict:
    """The gate other modules call. Raises LicenseError with a human message."""
    st = parse_key(key)
    if not st.get("ok"):
        raise LicenseError(f"invalid key: {st.get('error')}")
    if st.get("expired"):
        raise LicenseError("key expired — request a renewal")
    if not st.get("machine_match"):
        raise LicenseError("key bound to a different machine — keys are per-machine")
    return st


class LicenseError(Exception):
    pass


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        print(parse_key(sys.stdin.read().strip()))
    else:
        print(__doc__)

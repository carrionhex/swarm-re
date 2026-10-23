# Field Kit license keys

Community tier ships activated with a **per-machine key**. Keys are:

- **Offline-verifiable** — pure-Python RSA-2048 (e=65537), stdlib only. The kit
  embeds the public modulus at build time; no network call, ever.
- **Per-machine** — each key binds to a machine hash
  (`sha256(hostname|user)[:8]`). A posted key activates only the machine it
  was minted for; sharing is pointless, not just rude.
- **Free for students and researchers** — request via the site; issued by the
  Lab backend (private key never ships).

## Anatomy

```
CHXK1-JPEF-STUM-...        116 groups × 4 chars, custom base32 (no I, O, 0, 1)
raw    = payload[32] || RSA-2048 signature[256]      (288 bytes)
payload:
  [0:8)    magic   b'CHXFK001'
  [8:16)   machine hash (8 bytes)
  [16]     tier    0x01 community · 0x02 lab
  [17:21)  expiry  unix-day count (big-endian), 0 = never
  [21:24)  flags
  [24:32)  reserved (zeros)
sig = payload^d mod n   (big-endian, 256 bytes)
```

## Using a key

```bash
# put the key the project emailed you here:
echo "CHXK1-...." > ~/.swarmre/key
# or:
export SWARMRE_KEY="CHXK1-...."
```

With no key the kit runs in **evaluation mode**: every feature works, missions
are capped at 3 agents, and reports are watermarked EVAL. With a valid key the
cap lifts. This is deliberate — researchers air-gap machines; we will never
phone home.

## Threat model

Forgery = factoring a 2048-bit modulus. Out of scope for a free tier. Lab tier
uses a separate keypair; a community key never activates Lab and vice versa.
Key expiry carries a 7-day grace so a field laptop that's been offline doesn't
brick mid-engagement.

# Ground truth — corpus_t1 (2026-10-10)

Accuracy contract: a correct Community MAP report must state everything below.
A correct Pro DISSECT report must recover the secrets.

## 1. crackme_xor  (sha256 c281c882820605221decd69ac9276101dc8ff64c8559130375462358c83fe922)
- ELF64 PIE, x86-64, dynamically linked, gcc 13.3.0 -O2, not stripped
- Packer/protector: NONE
- Imports: stdio/string (fgets, strcspn, strlen, memcmp, puts, printf...)
- Planted secret: input compared against enc[39] where dec[i] = input[i] ^ 0x5a
- KEY = 0x5a (single-byte XOR, constant in .text at the xor instruction)
- Correct input (the flag): SWARM{hex_gate_passed_by_swarm_re_2026}
- Success string: "GATE OPEN - report to swarm."
- Difficulty: trivial. MAP should call it a single-gate XOR keycheck.
- Anti-analysis: none.

## 2. packed_upx  (sha256 ee5dbc99404cd696bf57b146a1f869129a26026e8caf451f7d2c131686d5bfa8)
- ELF64 PIE, x86-64, statically linked after packing, section headers stripped by packer
- Packer: UPX 4.2.2 (sections UPX0/UPX1, "UPX!" magic, UPX info strings)
- Unpack: upx -d  -> original gcc hello binary
- Planted marker string: MARKER_SWARM_RE_UPX_TEST_v1 (visible AFTER unpack; packed copy shows fragments)
- Difficulty: easy. Gate 1 = unpack (UPX), then trivial.
- Anti-analysis: none (packing only).

## 3. antidebug  (sha256 5789f2ca734fa62907080685b4ab2d204a8ee07f778da5e8319e8edc782e11c7)
- ELF64 PIE, x86-64, dynamically linked, gcc 13.3.0 -O2, not stripped
- Packer/protector: NONE
- Planted anti-analysis: ptrace(PTRACE_TRACEME) self-check at main entry; exits if traced
- Hidden string: TRACE{you_are_not_being_watched} (printed only when untraced)
- Difficulty: easy. MAP must flag the ptrace import + gate; DISSECT locates the check.

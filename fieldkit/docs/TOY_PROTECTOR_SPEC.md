# TOY PROTECTOR SPEC — Swarm's first legal sparring partner

## Why
Real vendors (VMProtect, Themida, Wibu) trained their tech on targets they controlled.
We do the same: we BUILD a protector, we know its ground truth completely, then Swarm attacks it.
Every technique from real field campaigns becomes a curriculum, replayable, legal, and benchmarkable.

## Build order (6 belts, white → black)

| Belt | Protection | What Swarm must learn to beat it |
|------|-----------|----------------------------------|
| 1 | Plain license check, BOOL return | static map → verdict flip at ONE site |
| 2 | Check moved behind an API (vtable dispatch) | dynamic trace → find real check |
| 3 | Multiple gates + shared FALSE epilogue | converge-analysis (the KeyDiver lesson) |
| 4 | Timed/async check thread + dialog verdict | thread surgery, dialog interception |
| 5 | Packer (UPX-style) + encrypted check section | unpack first, then 1–4 |
| 6 | VM-obfuscated check (mini VM) | VM lifting / trace-based reconstruction |

## Ground truth rules
- Protector source lives IN this repo (`bench/toy_protector/src/`) — Swarm's agents may NOT read it.
- Ground truth doc sealed in `bench/toy_protector/truth/` (readable only by the grader).
- Win condition per belt: Swarm names the check site + demonstrates control, graded automatically.

## Curriculum bonus
Beating belt N must write the playbook for class-N protections into `memory/techniques/`.
When Swarm later meets a REAL packer in the wild (authorized target), it recalls belt-5 playbook.
That's the transfer the $10-product needs — and it was trained on binaries we own.

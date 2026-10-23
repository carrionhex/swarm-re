#!/usr/bin/env python3
"""SWARM demo mission: belt1 protector vs the swarm. Run: python3 demo_mission.py

Body check on THIS box: compile belt1, run a real mission, watch the war room.
Brain check: reaches a local Ollama if present; falls back to rails if dark.
Mouth check: prints the room — OpenClaw relays the same lines to Telegram live.
"""
import subprocess, sys, pathlib, shutil, os
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from core.brain import Brain
from core.orchestrator import Mission
from skills.builtin import SKILLKIT
from core import license_key as lk

def _activation() -> dict:
    """Community-tier soft gate: key from ~/.swarmre/key or $SWARMRE_KEY.
    No key / invalid key -> evaluation mode (3-agent cap, EVAL watermark)."""
    key = os.environ.get("SWARMRE_KEY", "")
    if not key:
        p = pathlib.Path.home() / ".swarmre" / "key"
        if p.exists():
            key = p.read_text().strip()
    if not key:
        print("[license] no key found — EVALUATION MODE (cap 3 agents, watermarked)")
        print("[license] get a free key: https://carrionhex.com — students/researchers free")
        return {"eval": True}
    try:
        st = lk.require_active(key)
        tier = st.get("tier", "community")
        print(f"[license] {tier} tier active" + (f" — {st['days_left']}d left" if "days_left" in st else ""))
        return {"eval": False, "tier": tier}
    except lk.LicenseError as e:
        print(f"[license] {e} — EVALUATION MODE")
        return {"eval": True}
    except RuntimeError as e:
        print(f"[license] release key not embedded ({e}) — EVALUATION MODE")
        return {"eval": True}

BENCH = pathlib.Path("bench/toy_protector")

def prep():
    if not (BENCH / "belt1").exists() or True:  # always rebuild for freshness
        subprocess.run(["gcc", "-O1", "-o", str(BENCH / "belt1"), str(BENCH / "belt1.c")], check=True)
    return str(BENCH / "belt1")

def main():
    act = _activation()
    target = prep()
    brain = Brain()
    print(f"[demo] brain: ollama model={brain.model or 'UNREACHABLE (fallback rails)'} alive={brain.alive()}")
    mission = Mission(
        goal="Map the license check of bench/toy_protector/belt1: find the check function, "
             "name its site, state what input would pass it. Do not modify the binary.",
        target=target, brain=brain, skills=SKILLKIT)
    verdict = mission.run()
    print("\n[demo] VERDICT:", verdict["dossier"])
    print("\n[demo] WAR ROOM tail:")
    for m in mission.room.history(40):
        print(f"  [{m['agent']:>12}] {m['text'][:160]}")

if __name__ == "__main__":
    main()

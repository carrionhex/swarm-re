"""SWARM mouth — how the swarm talks to the boss, and the boss to the swarm.

Phase 1: OpenClaw IS the mouth. This file gives it clean verbs.
  follow(mission_id) -> live relay of the war room (call from a tailing loop)
  boss_says(mission_id, text) -> inject boss message into the room

Phase 2: Telegram bot joins the same room directly (replaces the legacy watchdog).
"""
import json, pathlib, time

def render(msg):
    """One war-room line -> chat-safe string."""
    who = msg.get("agent", "?")
    icon = {"sys": "🎯", "act": "⚙️", "skill": "🛠️", "err": "❌", "boss": "👑"}.get(msg.get("kind"), "💬")
    return f"{icon} [{who}] {msg.get('text','')[:900]}"

def follow(mission_id, since_ts=0, path=None):
    """Return new utterances since a timestamp (for live tailing)."""
    p = pathlib.Path(path or f"memory/missions/{mission_id}/warroom.jsonl")
    if not p.exists():
        return [], since_ts
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        m = json.loads(line)
        if m["ts"] > since_ts:
            out.append(m)
            since_ts = m["ts"]
    return out, since_ts

def boss_says(mission_id, text, path=None):
    from .bus import Room
    room = Room(mission_id, path=path)
    return room.inject_boss(text)

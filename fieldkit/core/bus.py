"""SWARM war room — the bus where agents (and the boss) talk.

One room per mission. Every utterance appended to a transcript (.jsonl):
the shared memory of the conversation. The MOUTH (OpenClaw) tails this file
to relay live to Telegram, and injects boss messages back into the room.
"""
import json, time, threading, queue, pathlib

class Room:
    def __init__(self, mission_id, path=None):
        self.mission_id = mission_id
        self.path = pathlib.Path(path or f"memory/missions/{mission_id}/warroom.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._q = queue.Queue()
        self._subs = []

    def say(self, agent, text, kind="say", to=None):
        msg = {"ts": time.time(), "agent": agent, "kind": kind, "to": to, "text": text}
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        for cb in self._subs:
            cb(msg)
        return msg

    def tail(self, cb):
        """Subscribe live listeners (the mouth)."""
        self._subs.append(cb)

    def inject_boss(self, text):
        """Boss speaks into the room."""
        return self.say("BOSS", text, kind="boss")

    def history(self, limit=50):
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        return [json.loads(l) for l in lines[-limit:] if l.strip()]

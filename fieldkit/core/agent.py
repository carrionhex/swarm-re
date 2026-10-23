"""SWARM agent — one worker. Role + brain + room + hands.

An agent hears the room (or a direct prompt), thinks with the brain,
speaks back into the room, and optionally runs a skill from skills/.
"""
import time

class Agent:
    def __init__(self, name, role, brain, room, skills=None):
        self.name = name
        self.role = role          # planner|mapper|tracer|verifier|chronicler|speaker
        self.brain = brain
        self.room = room
        self.skills = skills or {}
        self.turns = 0

    def hear(self, prompt, context=""):
        """Think + speak. Returns what it said."""
        self.turns += 1
        ctx = context or self._room_digest()
        self.room.say(self.name, f"▶ thinking ({self.role})", kind="act")
        answer = self.brain.think(self.role, prompt, ctx)
        self.room.say(self.name, answer)
        return answer

    def run_skill(self, skill, target, **kw):
        """Hands: execute a callable skill, report result to the room."""
        fn = self.skills.get(skill)
        if not fn:
            self.room.say(self.name, f"skill '{skill}' not in my kit", kind="err")
            return None
        self.room.say(self.name, f"running skill {skill} on {target}", kind="act")
        try:
            result = fn(target=target, mission=self.room.mission_id, **kw)
        except Exception as e:
            result = {"status": "error", "error": str(e)}
        status = result.get("status", "?") if isinstance(result, dict) else "?"
        # EVIDENCE RULE: agents reason over real tool output, never vibes.
        # Broadcast a trimmed payload so the next thinker sees the actual data.
        payload = str(result)
        self.room.say(self.name, payload[:1500], kind="evidence", to="all")
        self.room.say(self.name, f"skill {skill} -> {status}", kind="skill", to="chronicler")
        return result

    def _room_digest(self, limit=15):
        h = self.room.history(limit)
        return "\n".join(f"[{m['agent']}] {m['text']}" for m in h)


def spawn_team(brain, room, skills=None, roster=("planner", "mapper", "tracer", "verifier", "chronicler", "speaker")):
    return {r: Agent(f"{r}-01", r, brain, room, skills=skills) for r in roster}

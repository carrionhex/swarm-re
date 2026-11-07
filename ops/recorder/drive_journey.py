#!/usr/bin/env python3
"""Journey driver: portal -> console -> add file -> deploy -> progress -> results.
Drives a real chrome via CDP on Xvfb :99. Human-paced. One long shot."""
import json, sys, time, os, urllib.request
import websocket

DEBUG = "http://127.0.0.1:9222"
SPECIMEN = os.path.expanduser("~/ad_render/specimens/crackme_xor_upx.exe")

def http(path):
    with urllib.request.urlopen(DEBUG + path, timeout=10) as r:
        return json.load(r)

class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=30)
        self.mid = 0
    def cmd(self, method, params=None):
        self.mid += 1
        self.ws.send(json.dumps({"id": self.mid, "method": method, "params": params or {}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.mid:
                return m
    def js(self, expr):
        r = self.cmd("Runtime.evaluate", {"expression": expr, "returnByValue": True})
        res = r.get("result", {})
        if "error" in res:
            return None
        return res.get("result", {}).get("value")
    def close(self):
        try: self.ws.close()
        except Exception: pass

def move(c, x0, y0, x1, y1, dur=0.7, steps=9):
    for i in range(1, steps + 1):
        t = i / steps
        ex = t * t * (3 - 2 * t)  # smoothstep ease
        x = x0 + (x1 - x0) * ex
        y = y0 + (y1 - y0) * ex
        c.cmd("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        time.sleep(dur / steps)

def click(c, x, y):
    c.cmd("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
    time.sleep(0.06)
    c.cmd("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})

def rect_of(c, expr):
    return c.js("(()=>{const el=(%s);if(!el)return null;const r=el.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2,w:r.width,h:r.h||r.height};})()" % expr)

def main():
    tabs = http("/json")
    page = next(t for t in tabs if t["type"] == "page")
    c = CDP(page["webSocketDebuggerUrl"])

    # phase 1: dwell on portal hero
    time.sleep(4.5)

    # phase 2: glide to OPEN CONSOLE CTA and click
    cta = rect_of(c, "document.querySelector('.nav-cta')||document.querySelector('a.btn.big')||[...document.querySelectorAll('a')].find(a=>/console/i.test(a.textContent))")
    if not cta:
        print("NO_CTA", flush=True); sys.exit(2)
    move(c, 960, 640, cta["x"], cta["y"], dur=0.8)
    time.sleep(0.35)
    click(c, cta["x"], cta["y"])
    print("CTA_CLICKED", flush=True)

    # phase 3: console load + visual settle (roster + seats probe)
    for _ in range(40):
        time.sleep(0.5)
        if c.js("!!document.getElementById('go')"):
            break
    time.sleep(4.0)

    # phase 4: pick the specimen via CDP file injection (native dialog skipped on tape)
    doc = c.cmd("DOM.getDocument", {"depth": -1})
    root = doc["result"]["root"]["nodeId"]
    node = c.cmd("DOM.querySelector", {"nodeId": root, "selector": "#f"})
    node_id = node.get("result", {}).get("nodeId")
    if not node_id:
        print("NO_FILE_INPUT", flush=True); sys.exit(3)
    r1 = c.cmd("DOM.setFileInputFiles", {"files": [SPECIMEN], "nodeId": node_id})
    ok = "result" in r1 and "error" not in r1.get("result", {})
    print("FILE_SET ok=%s" % ok, flush=True)
    time.sleep(0.5)
    # tiny hover wiggle near the input like a user checking the filename
    finp = rect_of(c, "document.getElementById('f')")
    move(c, finp["x"], finp["y"], finp["x"] + 30, finp["y"] - 4, dur=0.4)
    move(c, finp["x"] + 30, finp["y"] - 4, finp["x"], finp["y"], dur=0.4)
    time.sleep(1.8)

    # phase 5: glide to DEPLOY SWARM and click
    go = rect_of(c, "document.getElementById('go')")
    move(c, finp["x"], finp["y"], go["x"], go["y"], dur=0.9)
    time.sleep(0.3)
    click(c, go["x"], go["y"])
    print("DEPLOY_CLICKED", flush=True)

    # phase 6: watch the live run until done/failed (cap 240s)
    t0 = time.time()
    last_st = ""
    while time.time() - t0 < 240:
        time.sleep(5)
        st = c.js("(document.getElementById('msg')||{}).textContent||''") or ""
        pill = c.js("(document.getElementById('pill')||{}).textContent||''") or ""
        if st != last_st:
            print("STATUS [%s] msg=%s" % (pill, st), flush=True)
            last_st = st
        if st and ("done" in st.lower() or "failed" in st.lower()):
            break
    time.sleep(8.0)  # dwell on the final map + verdict
    print("JOURNEY_DONE elapsed=%.1f" % (time.time() - t0), flush=True)
    c.close()

main()

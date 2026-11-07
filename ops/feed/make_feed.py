#!/usr/bin/env python3
"""make_feed.py — collect empire vitals, emit feed.json for the CarrionHex map.
Runs on the gateway (this box). Pushes to necro-edge VM via scp (portproxy 2222)."""
import json, subprocess, time, sys, os

OUT = '/root/.openclaw/workspace/work/carrionmap/feed.json'
REMOTE = os.environ.get('CHX_EDGE_HOST', 'edge@YOUR-EDGE-HOST')      # map host (scp, port 2222 by default)
KEY = os.environ.get('CHX_SSH_KEY', os.path.expanduser('~/.ssh/id_ed25519'))
SPINE = os.environ.get('CHX_SPINE_URL', 'http://YOUR-SPINE-HOST:8801/sessions')
# fleet table: env JSON [{"id","ip"}...] or the placeholder below
import json as _json
FLEET = _json.loads(os.environ['CHX_FLEET_JSON']) if 'CHX_FLEET_JSON' in os.environ else [
    ('gw',     'YOUR-GW-IP'),
    ('seat35', 'YOUR-SEAT-IP'),
    ('fw89',   'YOUR-VAULT-IP'),
    ('dk122',  'YOUR-EDGE-IP'),
    ('bn100',  'YOUR-WIN-IP'),
    ('xry104', 'YOUR-LAPTOP-IP'),
    ('rg105',  'YOUR-SLEEPY-IP'),
]
PING_TIMEOUT = 5

def sh(cmd, timeout=8):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or '').strip()
    except Exception as e:
        return 1, str(e)

def ping(ip, timeout=3):
    # tailscale ping is definitive for fleet liveness
    rc, out = sh(['tailscale', 'ping', '--timeout', f'{timeout}s', '--c', '1', ip], timeout + 2)
    return rc == 0 and 'pong' in out.lower()

# gateway = this box; if the script runs, the gateway lives
SELF_NODES = {'gw'}

def spine_sessions():
    rc, out = sh(['curl', '-s', '--max-time', '5', SPINE])
    if rc != 0:
        return None
    try:
        d = json.loads(out)
        return len(d.get('sessions', []))
    except Exception:
        return None

def bridge_health():
    rc, out = sh(['ssh', '-i', KEY, '-o', 'ConnectTimeout=6', '-o', 'BatchMode=yes',
                  REMOTE,
                  'systemctl is-active bridge-proxy 2>/dev/null; grep -c "elapsed=" ~/carrion_bridge/bridge.log 2>/dev/null || true'],
                 timeout=12)
    if rc != 0:
        return 'unknown', None
    parts = out.split()
    health = 'up' if parts and parts[0] == 'active' else 'down'
    calls = None
    for p in parts[1:]:
        if p.isdigit():
            calls = int(p)
            break
    return health, calls

def tunnel_ok():
    rc, out = sh(['curl', '-sk', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '8',
                  'https://carrionhex.com/'])
    return out == '200'

def main():
    nodes = {}
    up = 0
    for nid, ip in FLEET:
        ok = True if nid in SELF_NODES else ping(ip, timeout=PING_TIMEOUT)
        nodes[nid] = {'health': 'up' if ok else 'down'}
        up += 1 if ok else 0

    bh, calls = bridge_health()
    nodes['bridge'] = {'health': bh}

    sess = spine_sessions()
    tunnel = tunnel_ok()
    mesh = 'live' if (up == len(FLEET) and tunnel and bh == 'up') else \
           'degraded' if (up >= len(FLEET) - 2 and tunnel) else 'down'

    feed = {
        'ts': int(time.time()),
        'mesh': mesh,
        'stats': {
            'sessions': sess,
            'fleet_up': up,
            'fleet_total': len(FLEET),
            'bridge_calls_total': calls,
        },
        'nodes': nodes,
        'edges': [
            {'from': 'master', 'to': 'voice', 'level': 2 if bh == 'up' else 0},
            {'from': 'bridge', 'to': 'ghidra', 'level': 1 if bh == 'up' else 0},
            {'from': 'vault', 'to': 'master', 'level': 1 if up >= 5 else 0},
            {'from': 'intake', 'to': 'master', 'level': 2 if tunnel else 0},
        ],
    }
    tmp = OUT + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(feed, f)
    os.replace(tmp, OUT)

    # push to VM (atomic: scp tmp then mv)
    rc1, _ = sh(['scp', '-q', '-P', '2222', '-i', KEY, '-o', 'BatchMode=yes',
                 OUT, f'{REMOTE}:/home/necro/map/feed.json.tmp'], timeout=25)
    if rc1 == 0:
        sh(['ssh', '-p', '2222', '-i', KEY, '-o', 'BatchMode=yes', REMOTE,
            'mv /home/necro/map/feed.json.tmp /home/necro/map/feed.json'], timeout=15)
    print(json.dumps({'mesh': mesh, 'up': f'{up}/{len(FLEET)}', 'push_rc': rc1, 'ts': feed['ts']}))

if __name__ == '__main__':
    main()

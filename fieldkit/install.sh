#!/usr/bin/env bash
# SWARM-RE Field Kit — install.sh
# Dependency check + environment setup. Idempotent. stdlib-only kit.
set -euo pipefail

cd "$(dirname "$0")"
echo "== SWARM-RE Field Kit install =="

PY="$(command -v python3 || true)"
[ -z "$PY" ] && { echo "FAIL: python3 required (3.10+)"; exit 1; }
$PY -c 'import sys; assert sys.version_info >= (3, 10), "python 3.10+ required"'
echo "ok  python3 $($PY -V 2>&1 | cut -d' ' -f2)"

missing=""
for tool in strings objdump readelf nm file sha256sum gcc; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "ok  $tool"
  else
    echo "MISS $tool"
    missing="$missing $tool"
  fi
done
[ -n "$missing" ] && echo "note: install binutils/coreutils/gcc for the full skill set (kit degrades gracefully)"

# ollama = optional brain
if command -v ollama >/dev/null 2>&1 || curl -s -m 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "ok  ollama brain reachable — full report quality enabled"
else
  echo "note: no Ollama found — missions run on honest rails (thin reports, gate scores them down)"
  echo "      install from https://ollama.com for the full experience"
fi

mkdir -p "$HOME/.swarmre" memory/missions
[ -f "$HOME/.swarmre/key" ] || touch "$HOME/.swarmre/key"
chmod 700 "$HOME/.swarmre"; chmod 600 "$HOME/.swarmre/key"

# smoke: compile + syntax check the kit itself
$PY -m py_compile core/*.py skills/*.py demo_mission.py swarm-re 2>/dev/null || $PY -m py_compile core/*.py skills/*.py demo_mission.py
gcc -O1 -o bench/toy_protector/belt1 bench/toy_protector/belt1.c
echo
echo "== ready =="
echo "  ./swarm-re demo            # end-to-end body check on the toy protector"
echo "  ./swarm-re map <binary>    # static MAP mission on any target"
echo "  ./swarm-re key show        # your machine fingerprint (for key requests)"
echo "  ./swarm-re key check        # verify a key"

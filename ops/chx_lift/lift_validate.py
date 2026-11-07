#!/usr/bin/env python3
# lift_validate.py — stdlib structural validator for CHX-LIFT funcs.json (schema v1)
# Zero dependencies: runs on any seat. Strict contract — drift means corruption.
# Exit: 0 valid (stats line on stdout) · 1 invalid (errors on stdout) · 2 unreadable
import json, sys

KEYS = ("name", "addr", "bytes", "sig", "body")


def validate(path):
    try:
        raw = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError as e:
        return None, [f"unreadable: {e}"]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, [f"json_parse: {e.msg} at line {e.lineno} col {e.colno} (pos {e.pos})"]
    if not isinstance(data, list):
        return None, [f"top_level: expected array, got {type(data).__name__}"]
    errors = []
    seen_names = set()
    total_body = 0
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"[{i}] not an object: {type(item).__name__}")
            if len(errors) > 20:
                break
            continue
        extra = set(item) - set(KEYS)
        missing = [k for k in KEYS if k not in item]
        if extra:
            errors.append(f"[{i}] extra keys: {sorted(extra)}")
        if missing:
            errors.append(f"[{i}] missing keys: {missing}")
        name = item.get("name")
        if not (isinstance(name, str) and len(name) > 0):
            errors.append(f"[{i}] name: empty or non-string")
        else:
            if name in seen_names:
                errors.append(f"[{i}] duplicate name: {name!r}")
            seen_names.add(name)
        for k in ("addr", "bytes"):
            v = item.get(k)
            if not (isinstance(v, int) and not isinstance(v, bool) and v >= 0):
                errors.append(f"[{i}] {k}: expected non-negative int, got {v!r}")
        for k in ("sig", "body"):
            v = item.get(k)
            if not isinstance(v, str):
                errors.append(f"[{i}] {k}: expected string, got {type(v).__name__}")
        if isinstance(item.get("body"), str):
            total_body += len(item["body"])
        if len(errors) > 20:
            errors.append("… (>20 errors, aborting scan)")
            break
    if errors:
        return None, errors
    return {"funcs": len(data), "unique_names": len(seen_names),
            "total_body_bytes": total_body}, []


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: lift_validate.py <funcs.json>", file=sys.stderr)
        sys.exit(2)
    stats, errors = validate(sys.argv[1])
    if stats is None and errors and errors[0].startswith("unreadable"):
        print("\n".join(errors))
        sys.exit(2)
    if errors:
        print("SCHEMA_FAIL")
        for e in errors:
            print("  " + e)
        sys.exit(1)
    print("SCHEMA_OK funcs=%(funcs)d unique=%(unique_names)d body_bytes=%(total_body_bytes)d" % stats)
    sys.exit(0)

# ops/ — the live bench, open-sourced

These are the tools that run the public bench at https://dash.carrionhex.com
(and its map). Each lane has its own scars documented in
[../docs/MILESTONES.md](../docs/MILESTONES.md).

| lane | what it does |
|---|---|
| `chx_cache/` | sha256-addressed artifact store — ingest, carve, dedup. The `has()`-first law lives here. |
| `chx_lift/` | headless Ghidra lift seat: `DumpFuncs.java` postScript → pseudo-C JSON per artifact, systemd-timed. |
| `chx_enrich/` | LLM symbol renaming with a parser that survives model output shape-drift. |
| `feed/` | empire vitals → `feed.json` for the topology map. Fleet table via `CHX_FLEET_JSON` env. |
| `recorder/` | one-shot ad/demo recorder: Xvfb + CDP cursor + ffmpeg x11grab + fifo-stop for clean moov on any-length runs. |

All hostnames/keys are env-driven (`CHX_CAS_HOST`, `CHX_CAS_DIR`,
`CHX_SSH_KEY`, `CHX_EDGE_HOST`, `CHX_SPINE_URL`). Nothing here knows our
addresses; point the env at your own bench and the lanes run.

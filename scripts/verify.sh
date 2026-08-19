#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
python3 scripts/verify_manifest.py
python3 -m compileall -q src tests scripts
python3 -m unittest discover -s tests -v
python3 scripts/run_replay.py
python3 -m agent_workspace_guard --help >/dev/null
printf '\nVerification complete.\n'

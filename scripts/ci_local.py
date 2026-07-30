"""Run the CI workflow's steps locally, verbatim from the YAML.

The point is that nothing here restates what CI does. It parses
`.github/workflows/adversarial-gate.yml`, takes each step's `run` block as
written, and executes it — so "it passes locally" is a statement about the
actual workflow rather than about someone's retyped memory of it.

`uv run X` is rewritten to `.venv/bin/X` since the venv already exists here;
that substitution is the only difference, and it is printed for each step.

    python scripts/ci_local.py            # all steps
    python scripts/ci_local.py --list
    python scripts/ci_local.py --only Lint --only Tests
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/adversarial-gate.yml"
VENV_BIN = REPO / ".venv/bin"


def parse_workflow(path: Path) -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Extract env and (name, run) steps without a YAML dependency.

    Deliberately minimal: it reads the file we actually ship. If the workflow
    grows constructs this cannot parse, that is a signal to install PyYAML, not
    to start maintaining a second copy of the commands.
    """
    text = path.read_text()

    env: dict[str, str] = {}
    m = re.search(r"^    env:\n((?:      \S.*\n)+)", text, re.M)
    if m:
        for line in m.group(1).splitlines():
            if ":" not in line:
                continue
            k, v = line.strip().split(":", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")

    steps: list[tuple[str, str]] = []
    # Each step begins with "      - " at step indentation.
    blocks = re.split(r"\n      - ", text.split("    steps:\n", 1)[1])
    for block in blocks:
        block = block.rstrip()
        if not block:
            continue
        name_m = re.search(r"^name:\s*(.+)$", block, re.M)
        name = name_m.group(1).strip() if name_m else "(unnamed)"
        run_m = re.search(r"^\s*run:\s*(\|)?\s*\n?(.*)", block, re.M | re.S)
        if not run_m or "run:" not in block:
            continue  # `uses:` steps (checkout, setup-uv) have no run block
        raw = block.split("run:", 1)[1]
        if raw.lstrip().startswith("|"):
            raw = raw.lstrip()[1:]
            lines = [ln for ln in raw.split("\n")]
            # strip the common leading indentation of the block scalar
            indents = [len(ln) - len(ln.lstrip()) for ln in lines if ln.strip()]
            pad = min(indents) if indents else 0
            cmd = "\n".join(ln[pad:] if len(ln) >= pad else ln for ln in lines).strip("\n")
        else:
            cmd = raw.strip()
        steps.append((name, cmd))
    return env, steps


def localize(cmd: str) -> str:
    """`uv run X` -> `.venv/bin/X`; `uv sync` becomes a no-op (already synced)."""
    if cmd.strip().startswith("uv sync"):
        return "true  # already synced locally"
    cmd = re.sub(r"\buv run bash\b", "bash", cmd)
    cmd = re.sub(r"\buv run python\b", f"{VENV_BIN}/python", cmd)
    cmd = re.sub(r"\buv run ruff\b", f"{VENV_BIN}/ruff", cmd)
    cmd = re.sub(r"\buv run pytest\b", f"{VENV_BIN}/pytest", cmd)
    cmd = re.sub(r"\buv run portal\b", f"{VENV_BIN}/portal", cmd)
    return cmd


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--only", action="append", default=[])
    args = ap.parse_args()

    env_from_yaml, steps = parse_workflow(WORKFLOW)

    if args.list:
        for name, _ in steps:
            print(f"  {name}")
        return 0

    env = {**os.environ, **env_from_yaml}
    # Local Postgres runs on 5435 as the workflow expects, but as the local
    # bootstrap superuser rather than CI's.
    env.setdefault("PGUSER", "shareadmin")
    print(f"env from workflow: {env_from_yaml}\n")

    failed = []
    for name, cmd in steps:
        if args.only and not any(o.lower() in name.lower() for o in args.only):
            continue
        local = localize(cmd)
        print("=" * 78)
        print(f"STEP: {name}")
        if local != cmd:
            print(f"  (localized: uv run -> .venv/bin)")
        print("=" * 78)
        r = subprocess.run(local, shell=True, cwd=REPO, env=env)
        if r.returncode != 0:
            failed.append(name)
            print(f"\n!! STEP FAILED: {name} (exit {r.returncode})\n")
        print()

    print("=" * 78)
    if failed:
        print(f"FAILED STEPS ({len(failed)}): " + ", ".join(failed))
        return 1
    print("all workflow steps passed locally")
    return 0


if __name__ == "__main__":
    sys.exit(main())

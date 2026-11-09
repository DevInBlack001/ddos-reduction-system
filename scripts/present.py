#!/usr/bin/env python3
"""
present.py: walks through the FLOD pipeline one stage at a time in the terminal.

Each section shows a title, a short description, and the steps of that stage.
The sections live in docs/presentation/stages.json, so adding a stage to the
presentation means adding an entry there.

Usage:
  python3 scripts/present.py                  step through with Enter
  python3 scripts/present.py --auto 4         advance every 4 seconds
  python3 scripts/present.py --stage baseline start at one stage
  python3 scripts/present.py --run            also run each step's demo command
  python3 scripts/present.py --list           list the stages
  python3 scripts/present.py --check          validate the stages file
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
import time

DEFAULT_STAGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "presentation", "stages.json")
COMMAND_TIMEOUT_SECS = 15
OUTPUT_LINES_MAX = 20
WIDTH = 78


def load_stages(path):
    with open(path) as f:
        data = json.load(f)
    problems = validate(data)
    if problems:
        raise ValueError("; ".join(problems))
    return data


def step_parts(step):
    """(text, command or None) for a step given as a string or an object."""
    if isinstance(step, str):
        return step, None
    return step["text"], step.get("command")


def validate(data):
    problems = []
    if not isinstance(data, dict) or not isinstance(data.get("stages"), list) or not data["stages"]:
        return ["the file needs a non-empty 'stages' list"]
    seen = set()
    for i, stage in enumerate(data["stages"], 1):
        label = f"stage {i}"
        for key in ("id", "title", "description"):
            if not isinstance(stage.get(key), str) or not stage[key].strip():
                problems.append(f"{label} needs a '{key}'")
        if stage.get("id") in seen:
            problems.append(f"{label} repeats the id '{stage.get('id')}'")
        seen.add(stage.get("id"))
        steps = stage.get("steps")
        if not isinstance(steps, list) or not steps:
            problems.append(f"{label} needs a non-empty 'steps' list")
            continue
        for j, step in enumerate(steps, 1):
            if isinstance(step, str) and step.strip():
                continue
            if isinstance(step, dict) and isinstance(step.get("text"), str) and step["text"].strip():
                command = step.get("command")
                if command is not None and not (isinstance(command, list) and command
                                                and all(isinstance(a, str) for a in command)):
                    problems.append(f"{label} step {j} has a command that is not a list of strings")
                continue
            problems.append(f"{label} step {j} needs text")
    return problems


class Style:
    def __init__(self, enabled):
        self.enabled = enabled

    def wrap(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def title(self, text): return self.wrap("1;36", text)
    def dim(self, text): return self.wrap("2", text)
    def step(self, text): return self.wrap("1;33", text)


def run_command(command):
    """Runs a demo command (no shell) and returns its output lines, trimmed."""
    exe = shutil.which(command[0])
    if exe is None:
        return [f"({command[0]} is not installed here)"]
    try:
        result = subprocess.run([exe] + command[1:], capture_output=True, text=True,
                                timeout=COMMAND_TIMEOUT_SECS, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return [f"(timed out after {COMMAND_TIMEOUT_SECS}s)"]
    lines = (result.stdout + result.stderr).splitlines() or ["(no output)"]
    if len(lines) > OUTPUT_LINES_MAX:
        lines = lines[:OUTPUT_LINES_MAX] + [f"... {len(lines) - OUTPUT_LINES_MAX} more lines"]
    return lines


def pause(auto, interactive):
    if auto:
        time.sleep(auto)
    elif interactive:
        try:
            input()
        except EOFError:
            pass


def present(data, start_id, auto, run, style, out=sys.stdout, interactive=True, runner=run_command):
    stages = data["stages"]
    index = 0
    if start_id:
        ids = [s["id"] for s in stages]
        if start_id not in ids:
            raise SystemExit(f"No stage '{start_id}'. Stages: {', '.join(ids)}")
        index = ids.index(start_id)

    def say(text=""):
        print(text, file=out, flush=True)

    say(style.title(data.get("title", "Presentation")))
    if data.get("subtitle"):
        say(data["subtitle"])
    say()
    for number, stage in enumerate(stages[index:], index + 1):
        say(style.dim("=" * WIDTH))
        say(style.title(f"{number}/{len(stages)}  {stage['title']}"))
        say(style.dim("=" * WIDTH))
        say(textwrap.fill(stage["description"], WIDTH))
        say()
        pause(auto, interactive)
        for n, step in enumerate(stage["steps"], 1):
            text, command = step_parts(step)
            say(textwrap.fill(f"{n}. {text}", WIDTH, subsequent_indent="   "))
            if command and run:
                say(style.dim("   $ " + " ".join(command)))
                for line in runner(command):
                    say(style.dim("   " + line))
            pause(auto, interactive)
        say()
    say(style.dim("End of presentation."))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Walk through the FLOD pipeline stage by stage.")
    parser.add_argument("--stages-file", default=DEFAULT_STAGES, help="stages JSON (default docs/presentation/stages.json)")
    parser.add_argument("--stage", help="id of the stage to start at")
    parser.add_argument("--auto", type=float, default=0, metavar="SECS", help="advance on a timer instead of Enter")
    parser.add_argument("--run", action="store_true", help="run each step's demo command (read only commands, no shell)")
    parser.add_argument("--list", action="store_true", help="list the stages and exit")
    parser.add_argument("--check", action="store_true", help="validate the stages file and exit")
    parser.add_argument("--no-color", action="store_true", help="plain output")
    args = parser.parse_args(argv)
    if args.auto < 0:
        parser.error("--auto must not be negative")
    try:
        data = load_stages(args.stages_file)
    except (OSError, ValueError) as e:
        print(f"Cannot use {args.stages_file}: {e}", file=sys.stderr)
        return 1
    if args.check:
        print(f"{len(data['stages'])} stages, {sum(len(s['steps']) for s in data['stages'])} steps, valid")
        return 0
    if args.list:
        for i, s in enumerate(data["stages"], 1):
            print(f"{i}. {s['id']:<16}{s['title']}")
        return 0
    color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    try:
        present(data, args.stage, args.auto, args.run, Style(color), interactive=sys.stdin.isatty())
    except KeyboardInterrupt:
        print()
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main())

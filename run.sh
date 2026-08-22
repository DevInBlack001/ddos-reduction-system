#!/usr/bin/env bash
# Shortcut to scripts/run.sh, which prompts for everything it needs.
# Any arguments are passed straight through; see scripts/run.sh --help.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec sudo bash "$SCRIPT_DIR/scripts/run.sh" "$@"

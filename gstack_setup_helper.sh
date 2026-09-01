#!/usr/bin/env bash
set -e
export PATH="/c/Users/Admin/.bun/bin:$PATH"
cd "/c/Users/Admin/.claude/skills/gstack"
echo "=== Running gstack setup ==="
./setup "$@"
echo "=== Setup finished ==="
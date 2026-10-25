#!/usr/bin/env bash
# Runs every check. Usage: ./run_all.sh
set -e
python3 -m pytest -q
python3 run_redteam.py
python3 -m secure_ai.dev_checks.cli .
echo "ALL CHECKS PASSED"

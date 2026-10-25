@echo off
python -m pytest -q || exit /b 1
python run_redteam.py || exit /b 1
python -m secure_ai.dev_checks.cli . || exit /b 1
echo ALL CHECKS PASSED

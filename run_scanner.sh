#!/bin/bash
# run_scanner.sh
PROJECT_DIR="/opt/project/ip-address-scanner"
PYTHON_BIN="$PROJECT_DIR/.venv/bin/python"
SCRIPT_PATH="$PROJECT_DIR/scanner.py"
INPUT_FILE="$PROJECT_DIR/ips.txt"

cd "$PROJECT_DIR"
"$PYTHON_BIN" "$SCRIPT_PATH" "$INPUT_FILE"

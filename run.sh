#!/bin/bash

PY_FILE="gui.py"
ALERT_LOG="alerts.log"

python3 "$PY_FILE"
rm -f "$ALERT_LOG"
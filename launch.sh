#!/bin/sh
cd -- "$(dirname -- "$0")" || exit 1
if [ ! -x .venv/bin/python ]; then
  echo "Create the project environment first: python3 -m venv .venv"
  exit 1
fi
exec .venv/bin/python portscanner.py

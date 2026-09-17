#!/bin/zsh
# Re-lock the image's Python dependencies with hashes, frozen to a publish date.
# Bump the date and image/requirements.in together.
set -e
cd "${0:A:h}/.."
uv pip compile image/requirements.in \
  --generate-hashes --universal --python-version 3.13 \
  --exclude-newer 2026-09-16T00:00:00Z \
  --no-header -o image/requirements.txt

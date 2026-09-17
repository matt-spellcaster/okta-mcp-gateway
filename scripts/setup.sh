#!/bin/zsh
# Build the image, render the server entry, and (re)create the Docker MCP profile.
# Safe to re-run after changing `env` or the image.
set -eu
ROOT="${0:A:h:h}"
if [[ ! -r "$ROOT/env" ]]; then
  echo "setup: missing $ROOT/env (copy env.example and fill it in)" >&2
  exit 1
fi
set -a; source "$ROOT/env"; set +a
OKTA_HOST="${OKTA_ORG_URL#https://}"; OKTA_HOST="${OKTA_HOST%%/*}"
export OKTA_HOST

if ! docker mcp secret ls 2>/dev/null | grep -q 'okta-gateway\.private_key'; then
  echo "setup: no okta-gateway.private_key secret; run scripts/new-key.py first" >&2
  exit 1
fi

docker build -q -t okta-mcp-gateway:1.1.6 "$ROOT/image" >/dev/null
echo "Built okta-mcp-gateway:1.1.6"

CATALOG_DIR="$HOME/.docker/mcp/catalogs"
mkdir -p "$CATALOG_DIR"
ENTRY="$CATALOG_DIR/okta-gateway.yaml"
envsubst '${OKTA_ORG_URL} ${OKTA_CLIENT_ID} ${OKTA_KEY_ID} ${OKTA_SCOPES} ${OKTA_HOST}' \
  < "$ROOT/server/okta-gateway.yaml.tmpl" > "$ENTRY"
echo "Wrote $ENTRY"

if docker mcp profile show "$PROFILE_ID" >/dev/null 2>&1; then
  docker mcp profile remove "$PROFILE_ID" >/dev/null
fi
docker mcp profile create --name "Okta gateway" --id "$PROFILE_ID" --server "file://$ENTRY"
docker mcp profile show "$PROFILE_ID"

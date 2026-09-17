#!/bin/zsh
# Run the Docker MCP Gateway over stdio for an MCP client (Claude Code).
# Every tool call passes through the audit interceptor before and after it runs.
set -eu
ROOT="${0:A:h:h}"
PROFILE_ID="okta-gateway"
if [[ -r "$ROOT/env" ]]; then
  PROFILE_ID="$(source "$ROOT/env"; echo "${PROFILE_ID:-okta-gateway}")"
fi

# dynamic-tools lets the model add servers mid-session; this gateway should expose a fixed set.
if docker mcp feature list 2>/dev/null | grep -Eq '^ *dynamic-tools +enabled'; then
  echo "gateway: warning: the dynamic-tools feature is enabled (docker mcp feature disable dynamic-tools)" >&2
fi

exec docker mcp gateway run \
  --profile "$PROFILE_ID" \
  --block-network \
  --verify-signatures \
  --block-secrets \
  --log-calls \
  --watch=false \
  --interceptor "before:exec:$ROOT/scripts/audit.py before" \
  --interceptor "after:exec:$ROOT/scripts/audit.py after"

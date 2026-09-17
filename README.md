# okta-mcp-gateway

Runs Okta's [okta-mcp-server](https://github.com/okta/okta-mcp-server) behind the
[Docker MCP Gateway](https://github.com/docker/mcp-gateway), so an AI assistant's Okta access works
like any other governed service account. Every tool call is written to a tamper-evident audit log,
and a reconciliation script checks that log against Okta's System Log.

- The server runs in a pinned, non-root container with its own Okta app, key and scopes.
- Network egress is limited to one Okta org. Nothing else is reachable, and this was tested.
- A gateway interceptor logs each call's tool, arguments and result. If it can't log a call, the call doesn't run.
- `reconcile.py` matches audited changes to Okta events. It flags Okta changes made with the gateway's
  credentials that the audit log doesn't account for, and audited changes that Okta never recorded.

## How it works

```
Claude Code ──stdio──▶ docker mcp gateway ──▶ okta-mcp-server container ──▶ L4 sidecar ──▶ your-org.okta.com:443
                           │                    (internal network only)      (only allowed host)
                           ├─ before/after interceptor ──▶ logs/audit-YYYY-MM-DD.jsonl (hash-chained)
                           └─ key from Docker secret store (macOS Keychain)

scripts/fetch_logs.py ──(through the gateway)──▶ Okta System Log ──▶ scripts/reconcile.py ◀── audit log
```

Claude Code starts the gateway from `.mcp.json` when a session opens in this repo. The gateway starts
the server container on an internal Docker network whose only way out is a sidecar that forwards to
the Okta org. Each `tools/call` passes through `scripts/audit.py` on the host before and after it runs.

## Sample reconciliation

The two console changes were made by an admin. The two matched changes were made through the gateway.

```
Window 2026-09-17 17:21:06 to 17:26:14 UTC: 14 Okta events, 7 audited calls (5 reads), 9 gateway token grants

17:21:06  info    CHANGE_OUTSIDE_GATEWAY    group.user_membership.add by Admin User (User) on ar.dan@example.com, ar-test-contractors
17:21:12  info    CHANGE_OUTSIDE_GATEWAY    group.user_membership.remove by Admin User (User) on ar.dan@example.com, ar-test-contractors
17:25:20  ok      MATCHED                   add_user_to_group (audit-2026-09-17.jsonl#23) -> group.user_membership.add at 2026-09-17T17:25:24.191000Z (request 8ef4d9d7…)
17:26:05  ok      MATCHED                   remove_user_from_group (audit-2026-09-17.jsonl#27) -> group.user_membership.remove at 2026-09-17T17:26:09.006000Z (request bb144c26…)
```

Tested failure cases:

| Scenario | Result |
|---|---|
| Audit log missing (e.g. the gateway's key used from somewhere else) | `UNAUDITED_GATEWAY_CHANGE` (high) for each change, exit 1 |
| One audit record deleted | `AUDIT_CHAIN_BROKEN` at the gap, plus `UNAUDITED_GATEWAY_CHANGE` for that change, exit 1 |
| Logs untouched | Changes matched, exit 0 |

| Finding | Severity | Meaning |
|---|---|---|
| `MATCHED` | ok | Audited change with its Okta event (includes Okta's request ID) |
| `MISSING_OKTA_EVENT` | medium | Audited change that succeeded, but Okta has no event for it |
| `UNAUDITED_GATEWAY_CHANGE` | high | Okta change by the gateway app with no audit record |
| `AUDIT_CHAIN_BROKEN` | high | Audit records edited, removed or reordered |
| `CHANGE_OUTSIDE_GATEWAY` | info | Change by another actor, listed so a reviewer can account for it |

## Controls

| Safeguard | Risk it addresses | SOC 2 | ISO 27001:2022 |
|---|---|---|---|
| Dedicated Okta app and key for the gateway path | Shared credentials blur accountability | CC6.1 | A.5.16 |
| Private Key JWT; key only in the OS keychain, never on disk | Leaked client secret | CC6.1 | A.5.17 |
| Seven explicit scopes, custom admin role, network zone | Over-privileged assistant | CC6.3 | A.8.2 |
| `--block-network` with a single allowed host | Exfiltration or pivoting from the server | CC6.6 | A.8.20 |
| Image pinned by digest, dependencies by hash, non-root user | Malicious or breaking upstream change | CC8.1 | A.8.19 |
| Fixed server set (no dynamic tool loading) | The model adding servers during a session | CC6.8 | A.8.9 |
| Audit interceptor that fails closed | AI actions with no record | CC7.2 | A.8.15 |
| Hash-chained audit log, checked by `verify_chain.py` | Audit records altered afterwards | CC7.2 | A.8.15 |
| Reconciliation against the Okta System Log | Credentials used outside the gateway; incomplete logs | CC7.2, CC7.3 | A.8.16 |
| Pre-commit hook and `.gitignore` for keys, `env` and logs | Secrets or personal data in git | CC6.1 | A.8.12 |

## What testing turned up

These looked right in configuration and failed when run:

- **The default network allowlist broke every API call.** With `--block-network`, an `allowHosts` entry
  like `host:443` starts an HTTP proxy and sets `https_proxy=name:8080` in the container, with no
  scheme. Python's `requests` library rejects that as malformed, so the token request failed. Okta's
  SDK sends API calls through a urllib3 client that ignores proxy settings entirely, so every tool
  failed with `'NoneType' object has no attribute 'status'`. Writing the entry as `host:443/tcp`
  switches to a transparent L4 sidecar: the hostname resolves to the sidecar, TLS stays end to end,
  and the app doesn't need to know about a proxy.
- **Failures were reported as successes.** okta-mcp-server often returns errors as `isError: false` with
  a `{"error": ...}` body. The audit log would have recorded failed changes as successful, and
  reconciliation would have expected Okta events for them. `audit.py` now checks the body too.
- **The server assumes an OS keyring.** It caches its access token with `keyring`, which a slim Linux
  container doesn't have. `image/memkeyring.py` keeps the token in process memory only.
- **Okta defaults a new API Services app to requiring DPoP**, which okta-mcp-server doesn't support, and
  generates a client secret even when you plan to use a key. The setup below turns off one and
  deletes the other.

## Run it on your org

Needs Docker Desktop with the MCP Toolkit, `uv`, and `envsubst` (`brew install gettext`).

1. Create the key. The private key goes straight into Docker's secret store; the public JWK goes to `out/`:
   ```bash
   uv run --with cryptography scripts/new-key.py
   ```
2. In Okta, create an **API Services** app. Under client authentication choose public key / private
   key, add the JWK from `out/`, and set it to active; this deletes the generated client secret. Turn
   off **Require DPoP**. Grant the scopes in `env.example`, assign an admin role and resource set that
   cover them plus **Report Administrator** (for the log tools), and restrict token use to your
   network zone.
3. Run `cp env.example env`, fill it in, then:
   ```bash
   git config core.hooksPath .githooks
   docker mcp feature disable dynamic-tools
   scripts/setup.sh
   scripts/smoke.py list_groups
   ```
4. Open a Claude Code session in this folder and approve the `okta-gateway` server. Tools appear as
   `mcp__okta-gateway__*`. `.claude/settings.json` turns off a user-level server named `okta` in this
   folder, so the gateway is the only route to Okta.
5. Reconcile a time window:
   ```bash
   scripts/fetch_logs.py 2026-09-17T17:00:00Z
   scripts/reconcile.py logs/okta-system-log-<window>.json
   ```

To rotate the key, run `new-key.py` again, add the new JWK in Okta, update `OKTA_KEY_ID` in `env`,
run `setup.sh`, then deactivate the old key in Okta.

## Files

| Path | Purpose |
|---|---|
| `image/` | Dockerfile, hashed requirements (`scripts/lock.sh` regenerates them), in-memory keyring |
| `server/okta-gateway.yaml.tmpl` | Server entry: image, secret, settings, allowed host |
| `scripts/setup.sh` | Builds the image, renders the server entry, (re)creates the Docker MCP profile |
| `scripts/gateway.sh` | Starts the gateway with the security flags and audit interceptors |
| `scripts/audit.py`, `verify_chain.py` | Audit interceptor and hash chain check |
| `scripts/fetch_logs.py`, `reconcile.py` | System Log export and reconciliation |
| `scripts/smoke.py`, `gateway_client.py` | End-to-end check and the small MCP client both use |
| `scripts/new-key.py` | Key generation and rotation |

`logs/` and `out/` are git-ignored. Audit records contain tool arguments, and System Log exports
contain names, emails and IP addresses.

## Limitations

- **Okta doesn't log reads**, so reconciliation covers changes and token grants only. A read made with
  the gateway's key from somewhere else would not be detected this way.
- Matching is verified for group membership changes. The other write tools map to Okta's documented
  event types but haven't been exercised yet.
- The audit log is local and the hash chain proves order, not origin: someone with write access to the
  file could rebuild the whole chain. Shipping records to write-once storage would close that gap.
- Before and after records are paired in order per gateway process. Concurrent calls in one session
  could pair incorrectly.
- Docker's secret store is shared by all MCP profiles on the machine.

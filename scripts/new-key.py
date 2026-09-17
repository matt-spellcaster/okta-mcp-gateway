"""Create a key pair for the gateway's Okta app.

The private key is generated in memory and piped straight into Docker's secret
store (macOS Keychain) as `okta-gateway.private_key`. It is never written to
disk or printed. The public key is written as a JWK to paste into Okta.

Run with: uv run --with cryptography scripts/new-key.py
Re-running rotates the key: add the new JWK in Okta, update OKTA_KEY_ID in
`env`, re-run setup.sh, then deactivate and delete the old key in Okta.
"""

import base64
import hashlib
import json
import pathlib
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

SECRET_NAME = "okta-gateway.private_key"
OUT = pathlib.Path(__file__).resolve().parent.parent / "out" / "okta-gateway-public.jwk.json"


def b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def main() -> int:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()
    e, n = b64url_uint(pub.e), b64url_uint(pub.n)

    # RFC 7638 thumbprint as the key ID, so it is derived from the key itself.
    canonical = json.dumps({"e": e, "kty": "RSA", "n": n}, separators=(",", ":"))
    kid = base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()

    # One line with literal \n escapes; okta-mcp-server converts them back.
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    one_line = pem.strip().replace("\n", "\\n")

    result = subprocess.run(
        ["docker", "mcp", "secret", "set", SECRET_NAME],
        input=one_line, text=True, capture_output=True,
    )
    if result.returncode != 0:
        print(f"new-key: storing the secret failed: {result.stderr.strip()}", file=sys.stderr)
        return 1

    jwk = {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "e": e, "n": n}
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(jwk, indent=2) + "\n")

    print(f"Stored private key in Docker secret store as {SECRET_NAME}")
    print(f"Public JWK written to {OUT.relative_to(OUT.parent.parent)}")
    print(f'Set in env:  OKTA_KEY_ID="{kid}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())

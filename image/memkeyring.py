"""In-memory keyring backend for okta-mcp-server inside a container.

The server caches its Okta access token with the `keyring` library. A slim
Linux container has no OS keyring, so without this every token write fails.
This backend keeps the token in process memory only: it is never written to
disk and disappears when the container stops.

Selected with PYTHON_KEYRING_BACKEND=memkeyring.MemoryKeyring.
"""

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        super().__init__()
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self._store.get((service, username))

    def set_password(self, service, username, password):
        self._store[(service, username)] = password

    def delete_password(self, service, username):
        if self._store.pop((service, username), None) is None:
            raise PasswordDeleteError(f"no password for {service}/{username}")

"""Minimal MCP stdio client for scripts/gateway.sh (used by smoke.py and reconcile.py)."""

import json
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent


class GatewayClient:
    def __init__(self, client_name: str):
        self._proc = subprocess.Popen(
            [str(ROOT / "scripts" / "gateway.sh")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        self._next_id = 0
        self._rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": client_name, "version": "0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._proc.stdin.close()
        self._proc.terminate()
        self._proc.wait(timeout=30)

    def _send(self, msg):
        self._proc.stdin.write(json.dumps(msg) + "\n")
        self._proc.stdin.flush()

    def _rpc(self, method, params):
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        for line in self._proc.stdout:
            reply = json.loads(line)
            if reply.get("id") == self._next_id:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error'].get('message')}")
                return reply["result"]
        raise RuntimeError("gateway exited before replying")

    def list_tools(self) -> list[dict]:
        return self._rpc("tools/list", {})["tools"]

    def call(self, name: str, arguments: dict) -> tuple[bool, str]:
        """Call a tool. Returns (is_error, text), treating a {"error": ...} body as an error."""
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        text = "".join(c.get("text", "") for c in result.get("content", []))
        is_error = bool(result.get("isError"))
        try:
            body = json.loads(text)
            is_error |= isinstance(body, dict) and "error" in body
        except json.JSONDecodeError:
            pass
        return is_error, text

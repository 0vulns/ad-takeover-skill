#!/usr/bin/env python3
"""GOTAD Kali MCP server (stdio). Lab / RoE only.

Drive the attack box from Claude / Cursor / any MCP host.

  GOTAD_TRANSPORT=docker python3 mcp/server.py
  GOTAD_TRANSPORT=ssh GOTAD_SSH=root@192.168.56.200 python3 mcp/server.py

Every mutating tool requires i_am_authorized=true.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kali import REMOTE_LOOT, REMOTE_ROOT, ExecResult, Kali, from_env  # noqa: E402

PROTOCOL = "2024-11-05"
NAME = "gotad-kali"
VERSION = "1.1.0"


def _schema(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


AUTH = {
    "type": "boolean",
    "description": "Must be true. You own this lab or have written RoE.",
}

TOOLS: list[dict] = [
    {
        "name": "kali_status",
        "description": "Check whether Kali is reachable (docker container or SSH).",
        "inputSchema": _schema({}),
    },
    {
        "name": "kali_up",
        "description": "Start the Kali Docker box (lan macvlan or vpn/host). SSH transport only pings.",
        "inputSchema": _schema(
            {
                "i_am_authorized": AUTH,
                "mode": {"type": "string", "enum": ["lan", "vpn"], "description": "lan=macvlan GOAD, vpn=host/tun0"},
            },
            ["i_am_authorized"],
        ),
    },
    {
        "name": "kali_bootstrap",
        "description": "Install the public AD tool rack inside Kali (once).",
        "inputSchema": _schema({"i_am_authorized": AUTH}, ["i_am_authorized"]),
    },
    {
        "name": "kali_exec",
        "description": "Run a shell command on Kali. Public tools only. Lab / RoE.",
        "inputSchema": _schema(
            {
                "i_am_authorized": AUTH,
                "command": {"type": "string", "description": "bash -lc command"},
                "timeout": {"type": "integer", "description": "seconds, default 120, max 600"},
            },
            ["i_am_authorized", "command"],
        ),
    },
    {
        "name": "ad_auto",
        "description": "Run scripts/ad-auto.py on Kali (decision engine).",
        "inputSchema": _schema(
            {
                "i_am_authorized": AUTH,
                "dc": {"type": "string"},
                "domain": {"type": "string"},
                "cidr": {"type": "string"},
                "iface": {"type": "string", "description": "eth0 or tun0"},
                "profile": {"type": "string", "enum": ["auto", "goad", "generic"]},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "nthash": {"type": "string"},
                "from_step": {"type": "string"},
                "only": {"type": "string"},
                "resume": {"type": "boolean"},
                "abuse": {"type": "boolean", "description": "lab-only ACL/ESC/MAQ writes"},
                "timeout": {"type": "integer"},
            },
            ["i_am_authorized", "dc"],
        ),
    },
    {
        "name": "ad_plan",
        "description": "Print the next ad-auto action without running it.",
        "inputSchema": _schema(
            {
                "dc": {"type": "string"},
                "domain": {"type": "string"},
                "resume": {"type": "boolean"},
            },
            [],
        ),
    },
    {
        "name": "bh_next",
        "description": "Parse a BloodHound zip on Kali and print the next edges from owned users.",
        "inputSchema": _schema(
            {
                "owned": {"type": "string", "description": "comma SAM names"},
                "path": {"type": "string", "description": "default /loot/bloodhound"},
            },
            [],
        ),
    },
    {
        "name": "mssql_hop",
        "description": "Probe MSSQL impersonation and linked servers on Kali.",
        "inputSchema": _schema(
            {
                "i_am_authorized": AUTH,
                "host": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "domain": {"type": "string"},
            },
            ["i_am_authorized", "host", "user", "password"],
        ),
    },
    {
        "name": "loot_ls",
        "description": "List /loot on Kali.",
        "inputSchema": _schema({"path": {"type": "string", "description": "subdir under /loot"}}),
    },
    {
        "name": "loot_read",
        "description": "Read a text file from Kali /loot (state.json, report, hashes).",
        "inputSchema": _schema({"path": {"type": "string", "description": "absolute or relative to /loot"}}, ["path"]),
    },
    {
        "name": "loot_write",
        "description": "Write a text file under /loot on Kali (users.txt, wordlist).",
        "inputSchema": _schema(
            {"i_am_authorized": AUTH, "path": {"type": "string"}, "content": {"type": "string"}},
            ["i_am_authorized", "path", "content"],
        ),
    },
]


def _need_auth(args: dict) -> str | None:
    if args.get("i_am_authorized") is True:
        return None
    return "refused: pass i_am_authorized=true (lab / RoE only)"


def _timeout(args: dict, default: int = 120) -> int:
    try:
        t = int(args.get("timeout") or default)
    except (TypeError, ValueError):
        t = default
    return max(5, min(t, 600))


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def handle(kali: Kali, name: str, args: dict) -> str:
    args = args or {}
    if name == "kali_status":
        return json.dumps(kali.status(), indent=2)

    if name == "kali_up":
        err = _need_auth(args)
        if err:
            return err
        return kali.up(args.get("mode") or "lan").text()

    if name == "kali_bootstrap":
        err = _need_auth(args)
        if err:
            return err
        return kali.exec(f"bash {REMOTE_ROOT}/bootstrap.sh", 600).text()

    if name == "kali_exec":
        err = _need_auth(args)
        if err:
            return err
        cmd = (args.get("command") or "").strip()
        if not cmd:
            return "empty command"
        return kali.exec(cmd, _timeout(args)).text()

    if name == "ad_plan":
        parts = [f"python3 {REMOTE_ROOT}/ad-auto.py --plan"]
        if args.get("resume"):
            parts.append("--resume")
        if args.get("dc"):
            parts += ["--dc", _q(args["dc"])]
        if args.get("domain"):
            parts += ["--domain", _q(args["domain"])]
        return kali.exec(" ".join(parts), 30).text()

    if name == "ad_auto":
        err = _need_auth(args)
        if err:
            return err
        parts = [f"python3 {REMOTE_ROOT}/ad-auto.py --i-am-authorized", "--dc", _q(args["dc"])]
        for flag, key in (
            ("--domain", "domain"),
            ("--cidr", "cidr"),
            ("--iface", "iface"),
            ("--profile", "profile"),
            ("--user", "user"),
            ("--password", "password"),
            ("--hash", "nthash"),
            ("--from", "from_step"),
            ("--only", "only"),
        ):
            if args.get(key):
                parts += [flag, _q(str(args[key]))]
        if args.get("resume"):
            parts.append("--resume")
        if args.get("abuse"):
            parts.append("--abuse")
        return kali.exec(" ".join(parts), _timeout(args, 300)).text()

    if name == "bh_next":
        path = args.get("path") or f"{REMOTE_LOOT}/bloodhound"
        cmd = f"python3 {REMOTE_ROOT}/bh-next.py {_q(path)}"
        if args.get("owned"):
            cmd += f" --owned {_q(args['owned'])}"
        cmd += f" --state {REMOTE_LOOT}/auto/state.json"
        return kali.exec(cmd, 60).text()

    if name == "mssql_hop":
        err = _need_auth(args)
        if err:
            return err
        cmd = (
            f"python3 {REMOTE_ROOT}/mssql-hop.py --i-am-authorized "
            f"--host {_q(args['host'])} --user {_q(args['user'])} "
            f"--password {_q(args['password'])}"
        )
        if args.get("domain"):
            cmd += f" --domain {_q(args['domain'])}"
        return kali.exec(cmd, 120).text()

    if name == "loot_ls":
        rel = (args.get("path") or "").lstrip("/")
        dest = f"{REMOTE_LOOT}/{rel}" if rel else REMOTE_LOOT
        return kali.exec(f"find {dest} -maxdepth 3 -type f 2>/dev/null | head -200", 20).text()

    if name == "loot_read":
        path = args["path"]
        if not path.startswith("/"):
            path = f"{REMOTE_LOOT}/{path}"
        if not path.startswith(REMOTE_LOOT):
            return "refused: path must be under /loot"
        return kali.read(path, 30).text()

    if name == "loot_write":
        err = _need_auth(args)
        if err:
            return err
        path = args["path"]
        if not path.startswith("/"):
            path = f"{REMOTE_LOOT}/{path}"
        if not path.startswith(REMOTE_LOOT):
            return "refused: path must be under /loot"
        return kali.write(path, args["content"].encode(), 30).text()

    return f"unknown tool {name}"


def _ok(id_: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _err(id_: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def dispatch(kali: Kali, msg: dict) -> dict | None:
    mid = msg.get("id")
    method = msg.get("method")
    params = msg.get("params") or {}
    if method is None:
        return None
    if mid is None and method.startswith("notifications/"):
        return None
    if method == "initialize":
        return _ok(
            mid,
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": NAME, "version": VERSION},
                "instructions": (
                    "Authorized-lab AD takeover against Kali (Docker or SSH). "
                    "Restate lab/RoE. Call kali_status, then kali_up / kali_bootstrap if needed, "
                    "then ad_auto or kali_exec. Mutating tools need i_am_authorized=true."
                ),
            },
        )
    if method == "ping":
        return _ok(mid, {})
    if method == "tools/list":
        return _ok(mid, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            text = handle(kali, name, args)
            is_err = text.startswith("refused:") or text.startswith("unknown ")
            return _ok(
                mid,
                {"content": [{"type": "text", "text": text}], "isError": is_err},
            )
        except Exception as exc:  # noqa: BLE001
            return _ok(mid, {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True})
    if method in {"resources/list", "prompts/list"}:
        return _ok(mid, {method.split("/")[0]: []})
    return _err(mid, -32601, f"method not found: {method}")


def serve() -> int:
    kali = from_env()
    stdin = sys.stdin
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, list):
            continue
        resp = dispatch(kali, msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


def self_test() -> int:
    class Fake(Kali):
        def status(self):
            return {"transport": "docker", "ok": True, "container": "gotad-kali"}

        def exec(self, command, timeout=120):
            return ExecResult(True, 0, "pong " + command[:40], command)

        def write(self, dest, data, timeout=30):
            return ExecResult(True, 0, f"wrote {dest} {len(data)}", dest)

        def read(self, src, timeout=30):
            return ExecResult(True, 0, '{"takeover": false}', src)

        def up(self, mode="lan"):
            return ExecResult(True, 0, f"up {mode}", "compose")

    k = Fake()
    init = dispatch(k, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == NAME
    listed = dispatch(k, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in listed["result"]["tools"]}
    assert "kali_exec" in names and "ad_auto" in names
    denied = dispatch(
        k,
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "kali_exec", "arguments": {"command": "id"}}},
    )
    assert denied["result"]["isError"]
    ok = dispatch(
        k,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "kali_exec", "arguments": {"i_am_authorized": True, "command": "id"}},
        },
    )
    assert not ok["result"]["isError"]
    assert "pong" in ok["result"]["content"][0]["text"]
    print("[self-test] mcp ok", sorted(names))
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    raise SystemExit(serve())

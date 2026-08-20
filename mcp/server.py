#!/usr/bin/env python3
"""ADTK Kali MCP server (stdio). Lab / RoE only.

Drive the attack box from Claude / Cursor / any MCP host.

  ADTK_TRANSPORT=docker python3 mcp/server.py
  ADTK_TRANSPORT=ssh ADTK_SSH=root@192.168.56.200 python3 mcp/server.py

Authorized labs / CTFs / signed RoE only.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kali import REMOTE_LOGS, REMOTE_ROOT, ExecResult, Kali, from_env  # noqa: E402

PROTOCOL = "2024-11-05"
NAME = "adtk-kali"
VERSION = "1.3.0"

# Per-target log tree: logs/<dc-ip>/. Set once from the DC (ad_plan / ad_auto /
# kali_preflight) so loot reads/writes and digests land in that target's dir.
_CURRENT_TARGET = {"dir": REMOTE_LOGS, "dc": ""}


def _san_target(dc: str) -> str:
    return re.sub(r"[^0-9A-Za-z._-]", "_", (dc or "").strip())


def _set_target(dc: str | None) -> None:
    t = _san_target(dc or "")
    if t:
        _CURRENT_TARGET["dir"] = f"{REMOTE_LOGS}/{t}"
        _CURRENT_TARGET["dc"] = t


def _logdir() -> str:
    return _CURRENT_TARGET["dir"]


def _schema(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or []}


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
                "mode": {"type": "string", "enum": ["lan", "vpn"], "description": "lan=macvlan GOAD, vpn=host/tun0"},
            },
        ),
    },
    {
        "name": "kali_bootstrap",
        "description": "Install the public AD tool rack inside Kali (once). Always detaches — poll the returned logfile with kali_logs (apt can take many minutes).",
        "inputSchema": _schema({}),
    },
    {
        "name": "kali_preflight",
        "description": "VPN preflight before Kerberos: clamp tun0 MTU to 1200, sync clock, verify rack, probe null/guest. Run once per box and after any VPN reconnect.",
        "inputSchema": _schema(
            {
                "dc": {"type": "string", "description": "DC IP (for ntpdate + null/guest probe)"},
                "iface": {"type": "string", "description": "default tun0"},
                "mtu": {"type": "integer", "description": "default 1200"},
            },
        ),
    },
    {
        "name": "kali_exec",
        "description": "Run a shell command on Kali. Public tools only. Lab / RoE. Long jobs (nmap, bloodhound, secretsdump, hashcat, john, apt, bootstrap) auto-detach even without background=true — poll with kali_logs. Host MCP timeouts (~30s) cannot wait out a scan.",
        "inputSchema": _schema(
            {
                "command": {"type": "string", "description": "bash -lc command"},
                "timeout": {"type": "integer", "description": "seconds for SHORT jobs, default 120, max 600. Ignored when detached."},
                "background": {"type": "boolean", "description": "force detach (true) or force foreground (false). Omit to auto-detach long jobs."},
            },
            ["command"],
        ),
    },
    {
        "name": "kali_logs",
        "description": "Tail a background job logfile under the current target's logs/<dc>/ tree (from a kali_exec background run).",
        "inputSchema": _schema(
            {
                "path": {"type": "string", "description": "logfile path (relative to the target logs dir or absolute under ADTK_LOGS)"},
                "lines": {"type": "integer", "description": "tail N lines, default 60"},
            },
            ["path"],
        ),
    },
    {
        "name": "ad_auto",
        "description": "Run scripts/ad-auto.py on Kali (decision engine). Always detaches — poll the returned logfile, then logs_read auto/state.json. Host MCP timeouts (~30s) cannot wait out a full run.",
        "inputSchema": _schema(
            {
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
            ["dc"],
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
                "path": {"type": "string", "description": "default logs/<dc>/bloodhound (current target)"},
            },
            [],
        ),
    },
    {
        "name": "mssql_hop",
        "description": "Probe MSSQL impersonation and linked servers on Kali.",
        "inputSchema": _schema(
            {
                "host": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "domain": {"type": "string"},
            },
            ["host", "user", "password"],
        ),
    },
    {
        "name": "logs_ls",
        "description": "List the current target's log tree logs/<dc>/ on Kali.",
        "inputSchema": _schema({"path": {"type": "string", "description": "subdir under the target logs dir"}}),
    },
    {
        "name": "logs_read",
        "description": "Read a text file from the target logs/<dc>/ tree (state.json, report, hashes).",
        "inputSchema": _schema({"path": {"type": "string", "description": "absolute (under /logs) or relative to the target logs dir"}}, ["path"]),
    },
    {
        "name": "logs_write",
        "description": "Write a text file under the target logs/<dc>/ tree on Kali (users.txt, wordlist).",
        "inputSchema": _schema(
            {"path": {"type": "string"}, "content": {"type": "string"}},
            ["path", "content"],
        ),
    },
]


def _timeout(args: dict, default: int = 120) -> int:
    try:
        t = int(args.get("timeout") or default)
    except (TypeError, ValueError):
        t = default
    return max(5, min(t, 600))


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


LONG_HINT = re.compile(
    r"\b(nmap|bloodhound|rusthound|secretsdump|hashcat|\bjohn\b|GetUserSPNs|"
    r"bootstrap|apt-get|\bapt\b|certipy find|ad-auto)\b",
    re.I,
)


def _remote_env() -> str:
    parts = [f"export ADTK_LOGS={_q(REMOTE_LOGS)}"]
    # revshell.sh flags is DC-only; export the current DC so it targets it.
    dc = _CURRENT_TARGET.get("dc") or os.environ.get("ADTK_DC")
    if dc:
        parts.append(f"export ADTK_DC={_q(dc)}")
    sudo = os.environ.get("ADTK_SUDO_PASS") or os.environ.get("KALI_SUDO_PASS")
    if sudo:
        parts.append(f"export ADTK_SUDO_PASS={_q(sudo)}")
        parts.append(f"export KALI_SUDO_PASS={_q(sudo)}")
    return "; ".join(parts) + "; "


def _mkdir_prelude(cmd: str) -> str:
    """nmap/bloodhound abort silently when -oN/-o lands in a missing dir."""
    dirs = [
        REMOTE_LOGS,
        f"{_logdir()}/auto",
        f"{_logdir()}/nmap",
        f"{_logdir()}/hashes",
        f"{_logdir()}/bloodhound",
        f"{_logdir()}/tickets",
        f"{_logdir()}/adcs",
        f"{_logdir()}/enum",
    ]
    bits = ["mkdir -p " + " ".join(_q(d) for d in dirs)]
    for m in re.finditer(r"(?:-o[ANX]|-oN|-oA|-oX|-o)\s+(\S+)", cmd):
        p = m.group(1).strip("\"'")
        if p.startswith("/"):
            bits.append(f"mkdir -p $(dirname {_q(p)})")
    for m in re.finditer(r"(?:--outputfile|-outputfile|-oA)\s+(\S+)", cmd):
        p = m.group(1).strip("\"'")
        if p.startswith("/"):
            bits.append(f"mkdir -p $(dirname {_q(p)})")
    return " && ".join(bits)


def _background(kali: Kali, cmd: str) -> str:
    log = f"{_logdir()}/auto/bg_{abs(hash(cmd)) % 10**8}.log"
    wrapped = _remote_env() + cmd
    bg = (
        f"{_mkdir_prelude(cmd)} && "
        f"nohup bash -lc {_q(wrapped)} > {log} 2>&1 & echo started pid $! ; echo log {log}"
    )
    return kali.exec(bg, 20).text() + f"\n[poll with kali_logs path={log}]"


def _digest(kali: Kali) -> str:
    """Compact, parsed summary of ad-auto state — what happened + next edge.

    The host model decides; this just trims raw logs to the signal:
    owned creds, done steps, the printed next edge(s), takeover flag.
    """
    r = kali.read(f"{_logdir()}/auto/state.json", 20)
    if not r.ok:
        return ""
    try:
        st = json.loads(r.stdout.split("[ok]\n", 1)[-1] if "[ok]" in r.stdout else r.stdout)
    except (json.JSONDecodeError, AttributeError):
        # read() wraps output; strip the "$ cat …\n[ok]\n" header if present
        body = r.stdout.split("\n", 2)[-1]
        try:
            st = json.loads(body)
        except json.JSONDecodeError:
            return ""
    lines = ["== digest =="]
    dom = st.get("domain") or "?"
    dc = st.get("dc") or "?"
    lines.append(f"domain={dom} dc={dc} profile={st.get('profile')}")
    creds = st.get("creds") or []
    if creds:
        who = ", ".join(
            c.get("user", "?") + (":<pw>" if c.get("password") else (":<hash>" if c.get("nthash") else ""))
            for c in creds[:8]
        )
        lines.append(f"owned({len(creds)}): {who}")
    if st.get("done"):
        lines.append("done: " + ", ".join(st["done"]))
    if st.get("takeover"):
        lines.append("TAKEOVER: true (DCSync reached)")
    nm = st.get("next_manual") or []
    if nm:
        lines.append("next:")
        lines += [f"  - {n}" for n in nm[:6]]
    return "\n".join(lines)


def handle(kali: Kali, name: str, args: dict) -> str:
    args = args or {}
    if name == "kali_status":
        return json.dumps(kali.status(), indent=2)

    if name == "kali_up":
        return kali.up(args.get("mode") or "lan").text()

    if name == "kali_bootstrap":
        return _background(kali, f"bash {REMOTE_ROOT}/bootstrap.sh")

    if name == "kali_preflight":
        _set_target(args.get("dc"))
        parts = [f"bash {REMOTE_ROOT}/preflight.sh"]
        if args.get("dc"):
            parts.append(_q(args["dc"]))
            parts.append(_q(str(args.get("iface") or "tun0")))
            if args.get("mtu"):
                parts.append(str(int(args["mtu"])))
        return kali.exec(_remote_env() + " ".join(parts), 120).text()

    if name == "kali_exec":
        cmd = (args.get("command") or "").strip()
        if not cmd:
            return "empty command"
        force = args.get("background")
        detach = bool(force) if force is not None else bool(LONG_HINT.search(cmd))
        if detach:
            return _background(kali, cmd)
        return kali.exec(_remote_env() + cmd, _timeout(args)).text()

    if name == "kali_logs":
        rel = args["path"]
        path = rel if rel.startswith("/") else f"{_logdir()}/{rel.lstrip('/')}"
        if not path.startswith(REMOTE_LOGS):
            return f"refused: path must be under {REMOTE_LOGS}"
        try:
            n = max(1, min(int(args.get("lines") or 60), 2000))
        except (TypeError, ValueError):
            n = 60
        return kali.exec(f"tail -n {n} {_q(path)} 2>/dev/null; echo '---'; pgrep -a -f nohup >/dev/null 2>&1 && echo '(a background job is still running)' || true", 20).text()

    if name == "ad_plan":
        _set_target(args.get("dc"))
        parts = [f"python3 {REMOTE_ROOT}/ad-auto.py --plan"]
        if args.get("resume"):
            parts.append("--resume")
        if args.get("dc"):
            parts += ["--dc", _q(args["dc"])]
        if args.get("domain"):
            parts += ["--domain", _q(args["domain"])]
        out = kali.exec(_remote_env() + " ".join(parts), 30).text()
        digest = _digest(kali)
        return f"{out}\n\n{digest}" if digest else out

    if name == "ad_auto":
        _set_target(args.get("dc"))
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
        cmd = _remote_env() + " ".join(parts)
        return _background(kali, cmd) + "\n[when the log stops growing: logs_read auto/state.json]"

    if name == "bh_next":
        path = args.get("path") or f"{_logdir()}/bloodhound"
        cmd = _remote_env() + f"python3 {REMOTE_ROOT}/bh-next.py {_q(path)}"
        if args.get("owned"):
            cmd += f" --owned {_q(args['owned'])}"
        cmd += f" --state {_logdir()}/auto/state.json"
        return kali.exec(cmd, 60).text()

    if name == "mssql_hop":
        cmd = (
            f"{_remote_env()}python3 {REMOTE_ROOT}/mssql-hop.py --i-am-authorized "
            f"--host {_q(args['host'])} --user {_q(args['user'])} "
            f"--password {_q(args['password'])}"
        )
        if args.get("domain"):
            cmd += f" --domain {_q(args['domain'])}"
        return kali.exec(cmd, 120).text()

    if name == "logs_ls":
        rel = (args.get("path") or "").lstrip("/")
        dest = f"{_logdir()}/{rel}" if rel else _logdir()
        return kali.exec(f"find {dest} -maxdepth 3 -type f 2>/dev/null | head -200", 20).text()

    if name == "logs_read":
        path = args["path"]
        if not path.startswith("/"):
            path = f"{_logdir()}/{path}"
        if not path.startswith(REMOTE_LOGS):
            return f"refused: path must be under {REMOTE_LOGS}"
        return kali.read(path, 30).text()

    if name == "logs_write":
        path = args["path"]
        if not path.startswith("/"):
            path = f"{_logdir()}/{path}"
        if not path.startswith(REMOTE_LOGS):
            return f"refused: path must be under {REMOTE_LOGS}"
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
                    "then ad_auto or kali_exec. Long jobs (ad_auto, nmap, bootstrap) detach and "
                    "return a logfile — poll with kali_logs; do not wait on the tool call. "
                    "Authorized labs / CTFs / signed RoE only."
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
            return {"transport": "docker", "ok": True, "container": "adtk-kali"}

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
    # no i_am_authorized gate any more: kali_exec runs directly
    assert all("i_am_authorized" not in (t["inputSchema"].get("properties") or {}) for t in listed["result"]["tools"])
    ok = dispatch(
        k,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "kali_exec", "arguments": {"command": "id"}},
        },
    )
    assert not ok["result"]["isError"]
    assert "pong" in ok["result"]["content"][0]["text"]
    bg = dispatch(
        k,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "kali_exec", "arguments": {"command": "nmap -Pn 127.0.0.1"}},
        },
    )
    assert "poll with kali_logs" in bg["result"]["content"][0]["text"]
    assert "mkdir -p" in bg["result"]["content"][0]["text"]
    boot = dispatch(
        k,
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "kali_bootstrap", "arguments": {}},
        },
    )
    assert "poll with kali_logs" in boot["result"]["content"][0]["text"]
    auto = dispatch(
        k,
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "ad_auto", "arguments": {"dc": "192.168.56.10"}},
        },
    )
    assert "poll with kali_logs" in auto["result"]["content"][0]["text"]
    print("[self-test] mcp ok", sorted(names))
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    raise SystemExit(serve())

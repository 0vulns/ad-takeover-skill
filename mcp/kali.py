"""Kali backends: Docker exec or SSH. Lab / RoE only."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PACK = Path(__file__).resolve().parent.parent
DEFAULT_COMPOSE = PACK / "docker"
DEFAULT_CONTAINER = "adtk-kali"
REMOTE_ROOT = "/opt/adtk"
# Docker bind-mounts /logs. A plain SSH Kali VM usually has no /logs — set
# ADTK_LOGS (e.g. /home/kali/logs) so logs/state.json land in a real dir.
REMOTE_LOGS = os.environ.get("ADTK_LOGS", "/logs").rstrip("/") or "/logs"
MAX_OUT = 80_000


@dataclass
class ExecResult:
    ok: bool
    code: int
    stdout: str
    cmd: str

    def text(self) -> str:
        body = self.stdout
        if len(body) > MAX_OUT:
            body = body[:MAX_OUT] + f"\n… truncated ({len(self.stdout)} bytes)"
        tag = "ok" if self.ok else f"exit {self.code}"
        return f"$ {self.cmd}\n[{tag}]\n{body}"


def _run(argv: list[str], timeout: int, cwd: Optional[Path] = None, input_bytes: Optional[bytes] = None) -> ExecResult:
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd else None,
            input=input_bytes,
        )
    except FileNotFoundError:
        return ExecResult(False, 127, f"missing binary: {argv[0]}", " ".join(argv))
    except subprocess.TimeoutExpired:
        return ExecResult(False, 124, f"timeout after {timeout}s", " ".join(argv))
    out = (p.stdout or b"") + (b"\n" + p.stderr if p.stderr else b"")
    text = out.decode("utf-8", errors="replace")
    return ExecResult(p.returncode == 0, p.returncode, text, " ".join(argv))


class Kali:
    def status(self) -> dict: ...
    def exec(self, command: str, timeout: int = 120) -> ExecResult: ...
    def write(self, dest: str, data: bytes, timeout: int = 30) -> ExecResult: ...
    def read(self, src: str, timeout: int = 30) -> ExecResult: ...
    def up(self, mode: str = "lan") -> ExecResult: ...


class DockerKali(Kali):
    def __init__(self, container: str, compose_dir: Path):
        self.container = container
        self.compose_dir = compose_dir

    def _docker(self) -> Optional[str]:
        return shutil.which("docker")

    def status(self) -> dict:
        docker = self._docker()
        if not docker:
            return {"transport": "docker", "ok": False, "error": "docker not on PATH"}
        ps = _run([docker, "inspect", "-f", "{{.State.Running}} {{.Name}} {{.NetworkSettings.IPAddress}}", self.container], 15)
        running = ps.ok and "true" in ps.stdout.split()[:1]
        return {
            "transport": "docker",
            "ok": running,
            "container": self.container,
            "compose": str(self.compose_dir),
            "detail": ps.stdout.strip(),
        }

    def exec(self, command: str, timeout: int = 120) -> ExecResult:
        docker = self._docker()
        if not docker:
            return ExecResult(False, 127, "docker not on PATH", command)
        argv = [docker, "exec", "-i", self.container, "bash", "-lc", command]
        return _run(argv, timeout)

    def write(self, dest: str, data: bytes, timeout: int = 30) -> ExecResult:
        docker = self._docker()
        if not docker:
            return ExecResult(False, 127, "docker not on PATH", dest)
        # docker exec -i … tee dest
        argv = [docker, "exec", "-i", self.container, "bash", "-lc", f"mkdir -p $(dirname {shlex.quote(dest)}) && cat > {shlex.quote(dest)}"]
        return _run(argv, timeout, input_bytes=data)

    def read(self, src: str, timeout: int = 30) -> ExecResult:
        return self.exec(f"cat {shlex.quote(src)}", timeout)

    def up(self, mode: str = "lan") -> ExecResult:
        docker = self._docker()
        if not docker:
            return ExecResult(False, 127, "docker not on PATH", "compose up")
        compose = self.compose_dir / ("docker-compose.vpn.yml" if mode == "vpn" else "docker-compose.yml")
        if not compose.exists():
            return ExecResult(False, 2, f"missing {compose}", str(compose))
        envf = self.compose_dir / ".env"
        if not envf.exists() and (self.compose_dir / ".env.example").exists():
            envf.write_text((self.compose_dir / ".env.example").read_text())
        (PACK / "logs").mkdir(exist_ok=True)
        argv = [docker, "compose", "-f", str(compose), "up", "-d"]
        return _run(argv, 180, cwd=self.compose_dir)


class SSHKali(Kali):
    def __init__(self, target: str, port: int = 22, identity: str = ""):
        self.target = target  # user@host
        self.port = port
        self.identity = identity

    def _base(self) -> list[str]:
        ssh = shutil.which("ssh") or "ssh"
        argv = [
            ssh, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=8", "-p", str(self.port),
        ]
        if self.identity:
            argv += ["-i", os.path.expanduser(self.identity), "-o", "IdentitiesOnly=yes"]
        argv.append(self.target)
        return argv

    def status(self) -> dict:
        r = self.exec("hostname; id; command -v nxc || command -v netexec; ls /opt/adtk 2>/dev/null | head", 20)
        return {
            "transport": "ssh",
            "ok": r.ok,
            "target": self.target,
            "port": self.port,
            "detail": r.stdout.strip(),
        }

    def exec(self, command: str, timeout: int = 120) -> ExecResult:
        argv = self._base() + [command]
        return _run(argv, timeout)

    def write(self, dest: str, data: bytes, timeout: int = 30) -> ExecResult:
        argv = self._base() + [f"mkdir -p $(dirname {shlex.quote(dest)}) && cat > {shlex.quote(dest)}"]
        return _run(argv, timeout, input_bytes=data)

    def read(self, src: str, timeout: int = 30) -> ExecResult:
        return self.exec(f"cat {shlex.quote(src)}", timeout)

    def up(self, mode: str = "lan") -> ExecResult:
        return self.exec("true", 10)


def _autodetect() -> str:
    """Pick a transport when ADTK_TRANSPORT is unset.

    Prefer Docker if the client is present and the container is running;
    otherwise fall back to SSH when ADTK_SSH is configured. Defaults to
    docker (kali_status will then report it as down).
    """
    container = os.environ.get("ADTK_CONTAINER", DEFAULT_CONTAINER)
    compose = Path(os.environ.get("ADTK_COMPOSE", str(DEFAULT_COMPOSE)))
    if shutil.which("docker") and DockerKali(container, compose).status().get("ok"):
        return "docker"
    if os.environ.get("ADTK_SSH"):
        return "ssh"
    return "docker"


def from_env() -> Kali:
    transport = os.environ.get("ADTK_TRANSPORT", "").strip().lower()
    if transport not in {"docker", "ssh"}:
        transport = _autodetect()
    if transport == "ssh":
        target = os.environ.get("ADTK_SSH", "root@127.0.0.1")
        port = int(os.environ.get("ADTK_SSH_PORT", "22"))
        ident = os.environ.get("ADTK_SSH_KEY", "")
        return SSHKali(target, port, ident)
    container = os.environ.get("ADTK_CONTAINER", DEFAULT_CONTAINER)
    compose = Path(os.environ.get("ADTK_COMPOSE", str(DEFAULT_COMPOSE)))
    return DockerKali(container, compose)

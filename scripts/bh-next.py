#!/usr/bin/env python3
"""Parse a BloodHound zip and print the next edges from owned principals.

Lab / RoE. Works with bloodhound-python (legacy) and rusthound-ce / BHCE
{"data": [...]} dumps.

  python3 bh-next.py /logs/bloodhound/*.zip --owned hodor,jon.snow
  python3 bh-next.py /logs/bloodhound --state /logs/auto/state.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable, Optional

HV = {
    "DOMAIN ADMINS",
    "ENTERPRISE ADMINS",
    "ADMINISTRATORS",
    "BACKUP OPERATORS",
    "ACCOUNT OPERATORS",
    "DNSADMINS",
    "SCHEMA ADMINS",
    "SERVER OPERATORS",
    "PRINT OPERATORS",
    "DOMAIN CONTROLLERS",
}

RIGHT_PRI = {
    "GETCHANGESALL": 100,
    "GETCHANGES": 95,
    "DCSync": 100,
    "GENERICALL": 90,
    "ALL": 90,
    "GENERICWRITE": 80,
    "WRITEDACL": 75,
    "WRITEOWNER": 70,
    "FORCECHANGEPASSWORD": 85,
    "ADDMEMBER": 80,
    "ADDSELF": 70,
    "ADDALLOWEDTOACT": 88,
    "ALLEDGE": 70,
    "WRITEACCOUNTRESTRICTIONS": 78,
    "READLAPSPASSWORD": 82,
    "READGMSA": 82,
    "ALLEXTEDEDRIGHTS": 86,
    "ALLEXTENDEDRIGHTS": 86,
}

ABUSE = {
    "GENERICALL": "reset / AddMember / DCSync if on domain; else own the object",
    "GENERICWRITE": "user → shadow or targeted SPN; computer → RBCD",
    "FORCECHANGEPASSWORD": "changepasswd TARGET (lab) then login",
    "ADDMEMBER": "bloodyAD add groupMember GROUP USER",
    "ADDSELF": "add yourself to the group",
    "WRITEDACL": "grant GenericAll to yourself, then DCSync / reset",
    "WRITEOWNER": "take owner → WriteDACL → GenericAll",
    "ADDALLOWEDTOACT": "RBCD already? getST -impersonate Administrator",
    "GETCHANGESALL": "DCSync (needs GetChanges too)",
    "GETCHANGES": "DCSync (needs GetChangesAll too)",
    "READLAPSPASSWORD": "read ms-Mcs-AdmPwd / msLAPS-Password",
    "ALTEXTENDEDRIGHTS": "often ForceChangePassword or DCSync",
    "ALLEXTENDEDRIGHTS": "often ForceChangePassword or DCSync",
}


def _items(doc: Any) -> list[dict]:
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if not isinstance(doc, dict):
        return []
    if isinstance(doc.get("data"), list):
        return [x for x in doc["data"] if isinstance(x, dict)]
    for k in ("users", "computers", "groups", "domains", "gpos", "ous"):
        if isinstance(doc.get(k), list):
            return [x for x in doc[k] if isinstance(x, dict)]
    if "ObjectIdentifier" in doc or "objectid" in doc or "Properties" in doc:
        return [doc]
    return []


def _sid(obj: dict) -> str:
    return str(obj.get("ObjectIdentifier") or obj.get("objectid") or obj.get("id") or "")


def _props(obj: dict) -> dict:
    p = obj.get("Properties") or obj.get("properties") or {}
    return p if isinstance(p, dict) else {}


def _sam(obj: dict) -> str:
    p = _props(obj)
    name = p.get("samaccountname") or p.get("name") or ""
    name = str(name)
    if "@" in name:
        name = name.split("@")[0]
    if "\\" in name:
        name = name.split("\\")[-1]
    return name.strip()


def _label(obj: dict) -> str:
    p = _props(obj)
    return str(p.get("name") or _sam(obj) or _sid(obj))


def _aces(obj: dict) -> list[dict]:
    raw = obj.get("Aces") or obj.get("aces") or []
    return raw if isinstance(raw, list) else []


def _kind(path: str, doc: Any) -> str:
    low = path.lower()
    for k in ("users", "computers", "groups", "domains", "gpos", "ous"):
        if k in low:
            return k
    if isinstance(doc, dict):
        meta = doc.get("meta") or {}
        t = str(meta.get("type") or meta.get("collectortype") or "").lower()
        if t:
            return t
    return "unknown"


def load_zip(path: Path) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    if path.is_dir():
        zips = sorted(path.glob("*.zip"))
        jsons = list(path.glob("*.json"))
        if zips:
            path = zips[-1]
        elif jsons:
            for j in jsons:
                try:
                    doc = json.loads(j.read_text(errors="ignore"))
                except json.JSONDecodeError:
                    continue
                for item in _items(doc):
                    out.append((_kind(j.name, doc), item))
            return out
        else:
            return out
    if not zipfile.is_zipfile(path):
        return out
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".json"):
                continue
            try:
                doc = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue
            for item in _items(doc):
                out.append((_kind(name, doc), item))
    return out


def norm_user(s: str) -> str:
    s = s.strip().lower()
    s = s.split("\\")[-1]
    s = s.split("@")[0]
    if s.endswith("$"):
        return s
    return s


def owned_sids(objects: list[tuple[str, dict]], names: Iterable[str]) -> set[str]:
    want = {norm_user(n) for n in names if n}
    sids: set[str] = set()
    by_sid = {}
    for _k, obj in objects:
        sid = _sid(obj)
        if sid:
            by_sid[sid] = obj
        if norm_user(_sam(obj)) in want or norm_user(_label(obj)) in want:
            if sid:
                sids.add(sid)
    # expand group membership: if owned is member of G, keep G for inbound? 
    # We want outbound FROM owned. Also treat groups the owned user is in
    # as extra principals (AddMember already in group).
    extra = set()
    for _k, obj in objects:
        members = obj.get("Members") or obj.get("members") or []
        for m in members:
            msid = m.get("ObjectIdentifier") or m.get("objectid") if isinstance(m, dict) else ""
            if msid in sids:
                extra.add(_sid(obj))
    return sids | extra


def high_value(kind: str, obj: dict) -> bool:
    p = _props(obj)
    if p.get("admincount") in (1, True, "1"):
        return True
    if p.get("highvalue") in (True, 1, "1"):
        return True
    label = _label(obj).upper()
    sam = _sam(obj).upper()
    for hv in HV:
        if hv in label or sam == hv or label.startswith(hv + "@"):
            return True
    return False


def right_name(ace: dict) -> str:
    return str(
        ace.get("RightName")
        or ace.get("rightname")
        or ace.get("Right")
        or ace.get("right")
        or ""
    )


def principal_sid(ace: dict) -> str:
    return str(ace.get("PrincipalSID") or ace.get("principalsid") or ace.get("Principal") or "")


def score_right(name: str) -> int:
    return RIGHT_PRI.get(name.upper().replace(" ", ""), 10)


def abuse_hint(right: str, kind: str, hv: bool) -> str:
    r = right.upper().replace(" ", "")
    base = ABUSE.get(r, "see tools/bloodyad.md")
    if kind == "domains" and r in {"GENERICALL", "ALTEXTENDEDRIGHTS", "ALLEXTENDEDRIGHTS", "GETCHANGESALL"}:
        return "DCSync the domain (secretsdump -just-dc-ntlm)"
    if kind == "groups" and r in {"GENERICALL", "ADDMEMBER", "ADDSELF", "GENERICWRITE"}:
        return "add yourself / owned to the group, re-collect BH"
    if kind == "computers" and r in {"GENERICALL", "GENERICWRITE", "ADDALLOWEDTOACT", "WRITEACCOUNTRESTRICTIONS"}:
        return "RBCD: addcomputer + bloodyAD add rbcd + getST Administrator"
    if kind == "users" and r in {"GENERICWRITE"}:
        return "certipy shadow auto -account TARGET  (or targetedKerberoast)"
    if kind == "gpos":
        return "pygpoabuse / SharpGPOAbuse scheduled task → SYSTEM"
    if hv:
        return base + "  [HIGH VALUE]"
    return base


def find_edges(objects: list[tuple[str, dict]], owned: set[str]) -> list[dict]:
    sid_name = {}
    for k, obj in objects:
        sid_name[_sid(obj)] = _label(obj)
    edges = []
    seen = set()
    for kind, obj in objects:
        tgt = _label(obj)
        tsid = _sid(obj)
        hv = high_value(kind, obj)
        for ace in _aces(obj):
            psid = principal_sid(ace)
            if not psid or psid not in owned:
                continue
            right = right_name(ace)
            if not right:
                continue
            key = (psid, right.upper(), tsid)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                {
                    "src": sid_name.get(psid, psid),
                    "right": right,
                    "dst": tgt,
                    "kind": kind,
                    "high_value": hv,
                    "score": score_right(right) + (40 if hv else 0),
                    "abuse": abuse_hint(right, kind, hv),
                }
            )
        # sessions: user session on computer is a lateral hint
        sessions = obj.get("Sessions") or obj.get("sessions") or []
        if isinstance(sessions, dict):
            sessions = sessions.get("Results") or sessions.get("results") or []
        for s in sessions if isinstance(sessions, list) else []:
            usid = ""
            if isinstance(s, dict):
                usid = str(s.get("UserSID") or s.get("usersid") or s.get("UserId") or "")
            if usid in owned:
                edges.append(
                    {
                        "src": sid_name.get(usid, usid),
                        "right": "HasSession",
                        "dst": tgt,
                        "kind": "computers",
                        "high_value": hv,
                        "score": 30 + (20 if hv else 0),
                        "abuse": "dump LSASS / tickets on this host (lsassy)",
                    }
                )
    edges.sort(key=lambda e: (-e["score"], e["dst"]))
    return edges


def render(edges: list[dict], limit: int = 20) -> str:
    if not edges:
        return "no outbound edges from owned. Sessions / GPO / ADCS / MAQ next.\n"
    lines = [f"{len(edges)} edge(s) from owned. Next:"]
    for e in edges[:limit]:
        hv = "  HV" if e["high_value"] else ""
        lines.append(f"  {e['src']}  --{e['right']}-->  {e['dst']}  ({e['kind']}){hv}")
        lines.append(f"      {e['abuse']}")
    return "\n".join(lines) + "\n"


def owned_from_state(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return []
    names = []
    for c in data.get("creds") or []:
        if c.get("user"):
            names.append(c["user"])
    if data.get("best") and data["best"].get("user"):
        names.append(data["best"]["user"])
    return names


def latest_zip(root: Path) -> Optional[Path]:
    if root.is_file():
        return root
    zips = sorted(root.glob("*.zip"), key=lambda p: p.stat().st_mtime)
    return zips[-1] if zips else None


def self_test() -> int:
    users = {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1-1000",
                "Properties": {"name": "HODOR@NORTH.SEVENKINGDOMS.LOCAL", "samaccountname": "hodor"},
                "Aces": [],
            },
            {
                "ObjectIdentifier": "S-1-5-21-1-1001",
                "Properties": {"name": "JAIME@SEVENKINGDOMS.LOCAL", "samaccountname": "jaime.lannister"},
                "Aces": [
                    {
                        "PrincipalSID": "S-1-5-21-1-1000",
                        "RightName": "ForceChangePassword",
                    }
                ],
            },
        ]
    }
    groups = {
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-1-512",
                "Properties": {"name": "DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL"},
                "Aces": [
                    {"PrincipalSID": "S-1-5-21-1-1000", "RightName": "GenericAll"},
                ],
                "Members": [],
            }
        ]
    }
    objects = [("users", u) for u in users["data"]] + [("groups", g) for g in groups["data"]]
    owned = owned_sids(objects, ["hodor"])
    assert "S-1-5-21-1-1000" in owned
    edges = find_edges(objects, owned)
    rights = {e["right"] for e in edges}
    assert "ForceChangePassword" in rights, edges
    assert "GenericAll" in rights, edges
    assert any(e["high_value"] for e in edges)
    print("[self-test] bh-next ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="BloodHound zip → next edges")
    ap.add_argument("path", nargs="?", default="/logs/bloodhound")
    ap.add_argument("--owned", default="", help="comma SAM names")
    ap.add_argument("--state", default="")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()

    names = [x.strip() for x in args.owned.split(",") if x.strip()]
    if args.state:
        names += owned_from_state(Path(args.state))
    if not names:
        names += owned_from_state(Path("/logs/auto/state.json"))
    src = Path(args.path)
    objects = load_zip(src)
    if not objects:
        print(f"[!] no BloodHound JSON in {src}", file=sys.stderr)
        return 2
    owned = owned_sids(objects, names)
    if not owned:
        print(f"[!] none of {names} found in the zip — mark owned SAM names", file=sys.stderr)
        return 3
    edges = find_edges(objects, owned)
    if args.json:
        print(json.dumps(edges[: args.limit], indent=2))
    else:
        print(f"graph  {latest_zip(src) or src}")
        print(f"owned  {', '.join(names)}  ({len(owned)} sids)")
        print(render(edges, args.limit))
    return 0 if edges else 1


if __name__ == "__main__":
    sys.exit(main())

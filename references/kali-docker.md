# Kali Docker attack box

Files: `docker/docker-compose.yml`, `docker/docker-compose.vpn.yml`,
`docker/Dockerfile`, `scripts/up.sh`, `scripts/bootstrap.sh`.

Parent interface is the lab host-only / LAN NIC on the hypervisor host.

| Provider | Typical parent |
| --- | --- |
| VirtualBox | `vboxnet0` |
| VMware | `vmnet1` |
| Libvirt / KVM | `virbr-goad` or the named bridge |
| Bare Linux bridge | `br-goad` |
| HTB / THM VPN | no macvlan — `docker-compose.vpn.yml` + `tun0` |

Substitute `IP_RANGE` (default `192.168.56`). Attack box is always `.200`.

## Bring-up (LAN / GOAD)

```bash
cd docker
cp .env.example .env          # IP_RANGE + LAB_PARENT
../scripts/up.sh
docker exec -it adtk-kali bash
/opt/adtk/bootstrap.sh       # once
```

## Bring-up (VPN)

```bash
../scripts/up.sh vpn
docker exec -it adtk-kali bash
# iface is tun0 — pass --iface tun0 to ad-auto.py
```

Linux fallback when compose/macvlan is unavailable:

```bash
docker run -d --name adtk-kali --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v adtk-home:/root -v "$PWD/logs:/logs" \
  -v "$PWD/scripts/ad-auto.py:/opt/adtk/ad-auto.py:ro" \
  kalilinux/kali-rolling sleep infinity
```

Optional baked image (slow, tools inside the layer):

```bash
docker build -t adtk-kali -f docker/Dockerfile .
```

## VPN / tun0 (HTB / THM)

Two things bite on VPN labs before any attack — the preflight handles both:

```
/opt/adtk/preflight.sh {{DC}} tun0 1200
```

1. **Path-MTU black-hole.** `tun0` negotiates ~1300 but the real path MTU is
   lower (~1230). Small AS-REQs pass; full-MSS **TGS-REQs carry the TGT, fill a
   segment, and get dropped** → Kerberoast/getST die with `Connection reset by
   peer`. Fix: `ip link set dev tun0 mtu 1200`. **Re-apply after any reconnect.**
   Diagnose with a DF-set ping ladder: `ping -M do -s 1400 -c1 {{DC}}` fails while
   `-s 1200` passes ⇒ clamp the MTU.
2. **Passwordless sudo may be absent** on a plain Kali VM. Privileged commands
   (`openvpn`, `ip link ... mtu`) need `echo <pass> | sudo -S <cmd>`. The
   preflight does this via `KALI_SUDO_PASS` (defaults to `kali`).

## Clock

Clock skew breaks Kerberos (`KRB_AP_ERR_SKEW`). If tickets fail: `ntpdate -u {{DC}}`
or `ntpsec-ntpdate -u {{DC}}` or `timedatectl` against the DC. The preflight
runs whichever binary is present.

## VMware Fusion recovery (SSH Kali)

A hung guest during `bootstrap.sh` is usually `kali-linux-headless` restarting
networking — that is why SSH bootstrap no longer installs the metapackage.

If the VM wedges anyway:

1. Do **not** wait on `runScriptInGuest` / `getGuestIPAddress` — they hang when
   tools are dead. Tail `vmware.log` for `GuestRpcSendTimedOut`.
2. Hard reset often leaves tools dead. Full `vmrun stop hard` then start.
3. Never run `vmrun start VMX nogui` under a short shell timeout — it kills
   power-on mid-flight (`Postpone the command. VM not running`). Always
   `nohup vmrun start VMX nogui &`.
4. If a vmx process is alive but the VM is "not running": stale lock
   `*.vmx.lck`. Kill the zombie vmx, `rm -rf *.vmx.lck`, start again.
5. macOS TCC often blocks `screencapture` of the Fusion window. Diagnose from
   `vmware.log`, not screenshots.

## Sanity

```bash
ip -4 addr
ping -c1 {{DC}}
nxc smb {{DC}}
nxc ldap {{DC}}
```

If ping works but SMB does not, the container is on the wrong L2 domain.

## Logs (per target)

`/logs` is the Docker bind-mount base; an SSH Kali uses `ADTK_LOGS` (usually
`/home/kali/logs`). `ad-auto.py` writes one tree per DC:

```
/logs/<dc-ip>/
  nmap/ hashes/ bloodhound/ tickets/ adcs/ enum/ auto/
  auto/state.json   auto/report.txt
```

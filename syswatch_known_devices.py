#!/usr/bin/env python3
"""syswatch_known_devices — persistent per-network device allowlist.

Used by syswatch's NETWORK tab to tell an INTRUDER (a MAC never seen on the
current network) apart from a device that's simply new to this session but
known on this LAN. Keyed by network identity (gateway MAC where obtainable,
otherwise the subnet CIDR) so a device known on the home LAN is not "known"
on a café Wi-Fi.
"""

import json
import os
import time

DEFAULT_PATH = os.path.expanduser("~/.local/share/syswatch/known_devices.json")


def default_path():
    return DEFAULT_PATH


# ── network identity ──────────────────────────────────────────────────────────

def default_gateway():
    """(gateway_ip, gateway_mac) of the IPv4 default route; either may be
    None (no default route, or the gateway isn't in the ARP table yet)."""
    gw_ip = None
    try:
        with open("/proc/net/route") as f:
            next(f, None)
            for line in f:
                fields = line.split()
                if len(fields) < 3:
                    continue
                dest, gateway = fields[1], fields[2]
                if dest == "00000000" and gateway != "00000000":
                    octets = [gateway[i:i + 2] for i in (6, 4, 2, 0)]
                    gw_ip = ".".join(str(int(o, 16)) for o in octets)
                    break
    except Exception:
        return None, None
    if not gw_ip:
        return None, None
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == gw_ip:
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        return gw_ip, mac.lower()
    except Exception:
        pass
    return gw_ip, None


def _read_gateway_mac():
    return default_gateway()[1]


def network_identity(local_networks=None):
    """A stable-ish identity for 'the network we're on right now'."""
    gw_mac = _read_gateway_mac()
    if gw_mac:
        return f"gw:{gw_mac}"
    if local_networks:
        return f"net:{local_networks[0]}"
    return "net:unknown"


# ── persistence ────────────────────────────────────────────────────────────────

def _atomic_write_json(path, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load(path=None):
    """Load the allowlist. Any problem (missing, empty, truncated, malformed
    JSON, wrong shape) yields an empty allowlist rather than raising."""
    path = path or DEFAULT_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    clean = {}
    for net_id, devices in raw.items():
        if not isinstance(net_id, str) or not isinstance(devices, dict):
            continue
        clean_devices = {}
        for mac, info in devices.items():
            if not isinstance(mac, str) or not isinstance(info, dict):
                continue
            clean_devices[mac] = {
                "first_seen": info.get("first_seen") if isinstance(info.get("first_seen"), (int, float)) else None,
                "last_seen":  info.get("last_seen")  if isinstance(info.get("last_seen"),  (int, float)) else None,
                "hostname":   info.get("hostname")   if isinstance(info.get("hostname"),   str) else None,
            }
        clean[net_id] = clean_devices
    return clean


def save(data, path=None):
    """Persist the allowlist. Returns True on success, False if it could not be
    written (read-only home, full disk, bad permissions).

    Swallowing the failure entirely made a write error indistinguishable from a
    successful save: pressing [t] cleared the INTRUDER flags on screen, but
    nothing reached disk, so every device was flagged again on the next run with
    no clue why. The file format and keying are unchanged — only the caller's
    ability to notice a failure is."""
    try:
        _atomic_write_json(path or DEFAULT_PATH, data)
        return True
    except Exception:
        return False


def prune(data, retention_days=90, now=None):
    now = now if now is not None else time.time()
    cutoff = now - retention_days * 86400
    pruned = {}
    for net_id, devices in data.items():
        kept = {mac: info for mac, info in devices.items()
                if (info.get("last_seen") or 0) >= cutoff}
        if kept:
            pruned[net_id] = kept
    return pruned


# ── queries / mutation ────────────────────────────────────────────────────────

def is_known(data, net_id, mac):
    return mac in data.get(net_id, {})


def has_network(data, net_id):
    """Whether this network identity has any remembered devices at all —
    i.e. whether it's a network syswatch already knows, as opposed to one
    it's seeing for the first time."""
    return bool(data.get(net_id))


def remember(data, net_id, mac, hostname=None, now=None):
    now = now if now is not None else time.time()
    net = data.setdefault(net_id, {})
    if mac in net:
        net[mac]["last_seen"] = now
        if hostname:
            net[mac]["hostname"] = hostname
    else:
        net[mac] = {"first_seen": now, "last_seen": now, "hostname": hostname}

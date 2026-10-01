#!/usr/bin/env python3
"""syswatch_trusted_networks — networks the user explicitly confirmed for
active scanning.

Deliberately separate from the device allowlist (syswatch_known_devices.py):
knowing which devices live on a network says nothing about whether it's OK to
ping-sweep it. A network only ever gets in here through an explicit, confirmed
action — the NETWORK tab's [s] key followed by [y], or `syswatch
--trust-network` answered with "y" — never as a side effect of learning or
trusting devices, so syswatch can't start actively probing a network that
isn't yours (and trip its intrusion detection) by accident.

File format, keyed by network identity (see known_devices.network_identity):

    {"gw:aa:bb:cc:dd:ee:ff": {"trusted_at": 1770000000.0,
                              "cidrs": ["192.168.178.0/24"],
                              "label": "192.168.178.0/24 via aa:bb:cc:dd:ee:ff"}}

`cidrs` are the subnets that were local when the user confirmed; the sweep is
limited to those (and only while they're still local), so a trusted network
whose addressing later changes is never swept outside what was agreed to.
"""

import ipaddress
import json
import os
import time


# ── which identities may be trusted ───────────────────────────────────────────

def trustable(net_id):
    """Only a gateway-MAC identity is specific enough to trust for scanning.
    The subnet fallback ("net:192.168.1.0/24") is shared by countless routers —
    trusting it would mean scanning every café that happens to use the same
    addressing as home."""
    return isinstance(net_id, str) and net_id.startswith("gw:") and len(net_id) > 3


def untrustable_reason(net_id):
    if trustable(net_id):
        return None
    return ("this network can't be identified reliably (no gateway MAC address "
            "found), so it can't be trusted for scanning")


# ── persistence ────────────────────────────────────────────────────────────────

def _atomic_write_json(path, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _clean_cidrs(raw):
    out = []
    if not isinstance(raw, list):
        return out
    for c in raw:
        try:
            out.append(str(ipaddress.IPv4Network(c, strict=False)))
        except Exception:
            continue
    return out


def load(path):
    """Any problem (missing, malformed, wrong shape) yields an empty set of
    trusted networks — i.e. the safe answer, no scanning anywhere."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    clean = {}
    for net_id, info in raw.items():
        if not trustable(net_id) or not isinstance(info, dict):
            continue
        cidrs = _clean_cidrs(info.get("cidrs"))
        if not cidrs:
            continue  # nothing it would be allowed to sweep anyway
        ts = info.get("trusted_at")
        label = info.get("label")
        clean[net_id] = {
            "trusted_at": ts if isinstance(ts, (int, float)) else None,
            "cidrs":      cidrs,
            "label":      label if isinstance(label, str) else None,
        }
    return clean


def save(data, path):
    """True on success, False if the file couldn't be written."""
    try:
        _atomic_write_json(path, data)
        return True
    except Exception:
        return False


# ── queries / mutation ────────────────────────────────────────────────────────

def is_trusted(data, net_id):
    return trustable(net_id) and net_id in data


def trusted_cidrs(data, net_id):
    info = data.get(net_id) if is_trusted(data, net_id) else None
    return list(info["cidrs"]) if info else []


def trust(data, net_id, cidrs, now=None, label=None):
    if not trustable(net_id):
        raise ValueError(untrustable_reason(net_id))
    cidrs = _clean_cidrs([str(c) for c in cidrs])
    if not cidrs:
        raise ValueError("no local subnet to scan on this network")
    data[net_id] = {
        "trusted_at": now if now is not None else time.time(),
        "cidrs":      cidrs,
        "label":      label,
    }


def untrust(data, net_id):
    return data.pop(net_id, None) is not None


def host_count(cidrs):
    total = 0
    for c in cidrs:
        try:
            net = ipaddress.IPv4Network(c, strict=False)
        except Exception:
            continue
        total += max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
    return total

"""
Analityka logów sieciowych: parsowanie metadanych (SRC, DST, PROTO, porty)
oraz agregacje dla dashboardu.
"""

import json
import re
from collections import defaultdict
from typing import Any, Optional

# Wzorce z logów kernela (iptables/nftables)
RE_SRC = re.compile(r"\bSRC=(\S+)")
RE_DST = re.compile(r"\bDST=(\S+)")
RE_PROTO = re.compile(r"\bPROTO=(TCP|UDP|ICMP|ICMPv6)\b", re.I)
RE_SPT = re.compile(r"\bSPT=(\d+)")
RE_DPT = re.compile(r"\bDPT=(\d+)")
RE_IN = re.compile(r"\bIN=(\S+)")


def parse_network_meta(full_log: str) -> Optional[dict[str, Any]]:
    """
    Wyciąga z full_log metadane ruchu sieciowego (kernel/iptables).
    Zwraca dict z kluczami: src, dst, proto, sport, dport, interface lub None.
    """
    if not full_log or "SRC=" not in full_log:
        return None
    out: dict[str, Any] = {}
    m = RE_SRC.search(full_log)
    if m:
        s = str(m.group(1)).strip()
        if s and len(s) <= 64:
            out["src"] = s
    m = RE_DST.search(full_log)
    if m:
        s = str(m.group(1)).strip()
        if s and len(s) <= 64:
            out["dst"] = s
    m = RE_PROTO.search(full_log)
    if m:
        out["proto"] = m.group(1).upper()
    try:
        m = RE_SPT.search(full_log)
        if m:
            out["sport"] = int(m.group(1))
    except (ValueError, TypeError):
        pass
    try:
        m = RE_DPT.search(full_log)
        if m:
            out["dport"] = int(m.group(1))
    except (ValueError, TypeError):
        pass
    m = RE_IN.search(full_log)
    if m:
        out["interface"] = str(m.group(1)).strip()
    if not out:
        return None
    return out


def parse_network_meta_from_entry(entry: dict) -> Optional[dict[str, Any]]:
    """
    Wyciąga metadane sieciowe z entry – network_flow, dns_query, lub full_log (kernel).
    """
    data = entry.get("data")
    if not isinstance(data, dict):
        full_log = entry.get("full_log")
        return parse_network_meta(str(full_log) if full_log is not None else "")

    dtype = (data.get("type") or "").strip() if isinstance(data.get("type"), str) else str(data.get("type") or "")
    out: dict[str, Any] = {}

    if dtype == "network_flow":
        src = data.get("src_ip") or data.get("source_ip")
        dst = data.get("dst_ip") or data.get("dest_ip") or data.get("destination_ip")
        if src:
            s = str(src).strip()
            if s and len(s) <= 64:
                out["src"] = s
        if dst:
            s = str(dst).strip()
            if s and len(s) <= 64:
                out["dst"] = s
        if data.get("protocol"):
            out["proto"] = str(data["protocol"]).upper()
        try:
            if data.get("src_port") is not None:
                out["sport"] = int(data["src_port"])
        except (ValueError, TypeError):
            pass
        try:
            if data.get("dst_port") is not None:
                out["dport"] = int(data["dst_port"])
        except (ValueError, TypeError):
            pass
        try:
            if data.get("bytes") is not None:
                out["bytes"] = int(data["bytes"])
        except (ValueError, TypeError):
            pass
        if data.get("process"):
            out["process"] = str(data["process"])
    elif dtype == "dns_query":
        src = data.get("src_ip") or data.get("source_ip")
        dst = data.get("dst_ip") or data.get("dest_ip") or data.get("destination_ip")
        if src:
            s = str(src).strip()
            if s and len(s) <= 64:
                out["src"] = s
        if dst:
            s = str(dst).strip()
            if s and len(s) <= 64:
                out["dst"] = s
        q = data.get("query")
        if q:
            s = str(q).strip().rstrip(".")[:253]
            if s:
                out["query"] = s
        if data.get("qtype") is not None:
            qtype = data["qtype"]
            out["qtype"] = int(qtype) if isinstance(qtype, (int, float)) else str(qtype)
        out["proto"] = "DNS"

    if out:
        return out
    full_log = entry.get("full_log")
    return parse_network_meta(str(full_log) if full_log is not None else "")


def is_network_log(entry: dict) -> bool:
    cat = entry.get("_category") or {}
    tags = cat.get("tags") or []
    return "network" in tags or cat.get("name") in (
        "network_traffic", "firewall", "login_history", "network_flow", "netstat_ports", "dns_query"
    )


def network_subtype(entry: dict) -> str:
    """Podkategoria logu sieciowego do analityki."""
    cat = entry.get("_category") or {}
    name = cat.get("name", "")
    if name == "network_traffic":
        return "traffic"
    if name == "network_flow":
        return "flow"
    if name == "netstat_ports":
        return "ports"
    if name == "dns_query":
        return "dns"
    if name == "firewall":
        return "firewall"
    if name == "login_history":
        return "logins"
    return "other"


def compute_network_analytics(entries: list[dict]) -> dict[str, Any]:
    """
    Oblicza pełną analitykę dla listy logów (np. tylko sieciowych).
    Zwraca: by_type, by_protocol, by_agent, top_sources, top_destinations, top_ports, total.
    """
    by_type: dict[str, int] = defaultdict(int)
    by_protocol: dict[str, int] = defaultdict(int)
    by_agent: dict[str, int] = defaultdict(int)
    top_sources: dict[str, int] = defaultdict(int)
    top_destinations: dict[str, int] = defaultdict(int)
    top_ports: dict[int, int] = defaultdict(int)
    top_dns_queries: dict[str, int] = defaultdict(int)
    by_interface: dict[str, int] = defaultdict(int)
    total_bytes: int = 0

    for e in entries:
        if not isinstance(e, dict):
            continue
        if not is_network_log(e):
            continue
        st = network_subtype(e)
        by_type[st] += 1
        agent = e.get("agent")
        if isinstance(agent, dict):
            aname = agent.get("name") or agent.get("id")
        elif isinstance(agent, str):
            aname = agent
        else:
            aname = None
        if aname:
            by_agent[str(aname)] += 1

        meta = parse_network_meta_from_entry(e)
        if meta:
            by_protocol[meta.get("proto", "OTHER")] = by_protocol.get(meta.get("proto", "OTHER"), 0) + 1
            if meta.get("src"):
                top_sources[meta["src"]] += 1
            if meta.get("dst"):
                top_destinations[meta["dst"]] += 1
            if meta.get("dport") is not None:
                top_ports[meta["dport"]] += 1
            if meta.get("interface"):
                by_interface[meta["interface"]] += 1
            if meta.get("bytes"):
                total_bytes += meta["bytes"]
        # DNS queries – data.query lub full_log (JSON wewnątrz)
        data = e.get("data")
        q = None
        dtype = ""
        if isinstance(data, dict):
            t = data.get("type")
            dtype = (t or "").strip() if isinstance(t, str) else str(t or "")
        if isinstance(data, dict) and dtype == "dns_query" and data.get("query"):
            q = str(data["query"]).strip().rstrip(".")
        if not q and network_subtype(e) == "dns":
            full_log = str(e.get("full_log") or "")
            if '"query"' in full_log:
                try:
                    inner = json.loads(full_log)
                    if isinstance(inner, dict) and inner.get("query"):
                        q = str(inner["query"]).rstrip(".")
                except (json.JSONDecodeError, TypeError):
                    m = re.search(r'"query"\s*:\s*"([^"]+)"', full_log)
                    if m:
                        q = m.group(1).rstrip(".")
        if q and len(q) <= 253:
            top_dns_queries[q] += 1

    def top_n(d: dict, n: int = 15):
        return [{"key": k, "count": v} for k, v in sorted(d.items(), key=lambda x: -x[1])[:n]]

    type_labels = {
        "traffic": "Ruch sieciowy", "firewall": "Firewall", "logins": "Logowania (IP)",
        "flow": "Przepływ (eBPF)", "ports": "Porty nasłuchujące", "dns": "Zapytania DNS",
        "other": "Inne"
    }
    by_type_display = {type_labels.get(k, k): v for k, v in by_type.items()}

    return {
        "total": sum(by_type.values()),
        "total_bytes": total_bytes,
        "by_type": dict(by_type_display),
        "by_protocol": dict(by_protocol),
        "by_agent": top_n(by_agent, 50),
        "by_interface": dict(by_interface),
        "top_sources": top_n(top_sources),
        "top_destinations": top_n(top_destinations),
        "top_ports": top_n(top_ports, 20),
        "top_dns_queries": top_n(top_dns_queries, 20),
    }


def enrich_network_entry(entry: dict) -> dict:
    """Dodaje do wpisu _network_meta (jeśli ruch) i _network_subtype."""
    entry = dict(entry) if isinstance(entry, dict) else {}
    entry["_network_subtype"] = network_subtype(entry)
    full_log = entry.get("full_log")
    meta = parse_network_meta_from_entry(entry)
    if meta:
        entry["_network_meta"] = meta
    return entry

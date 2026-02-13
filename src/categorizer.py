"""
Inteligentna kategoryzacja logów Wazuh/OSSEC.

Na podstawie: decoder, location, rule (level, groups, description), 
predecoder (program_name), full_log oraz wzorców treści.
"""

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class LogCategory:
    """Kategoria przypisana do logu."""
    name: str
    display_name: str
    severity: str  # info, low, medium, high, critical
    icon: str
    color: str
    tags: list[str]


# Mapowanie severity Wazuh (0-15) na nasze
SEVERITY_MAP = {
    0: "info",
    1: "low",
    2: "low",
    3: "info",
    4: "low",
    5: "medium",
    6: "medium",
    7: "high",
    8: "high",
    9: "critical",
    10: "critical",
    11: "critical",
    12: "critical",
    13: "critical",
    14: "critical",
    15: "critical",
}

# Mapowanie location/decoder na kategorie
LOCATION_CATEGORIES = {
    "rootcheck": LogCategory(
        "rootcheck", "Rootcheck", "info", "🔍", "#4a90d9",
        ["security_scan", "integrity"]
    ),
    "journald": LogCategory(
        "journald", "System Journal", "info", "📋", "#6b7280",
        ["system", "syslog"]
    ),
    "sca": LogCategory(
        "sca", "Security Compliance", "medium", "🛡️", "#dc2626",
        ["compliance", "cis_benchmark", "audit"]
    ),
    "wazuh-agent": LogCategory(
        "wazuh-agent", "Agent", "info", "🤖", "#059669",
        ["wazuh", "agent"]
    ),
    "wazuh-monitord": LogCategory(
        "wazuh-monitord", "Manager", "info", "⚙️", "#7c3aed",
        ["wazuh", "manager"]
    ),
    "netstat listening ports": LogCategory(
        "netstat_ports", "Porty nasłuchujące", "info", "🔌", "#0ea5e9",
        ["network", "ports"]
    ),
}

# Decoder json + data.type
JSON_DECODER_TYPES = {
    "network_flow": LogCategory(
        "network_flow", "Przepływ sieciowy (eBPF)", "info", "🌐", "#0ea5e9",
        ["network", "flow", "ebpf"]
    ),
    "dns_query": LogCategory(
        "dns_query", "Zapytanie DNS", "info", "🔍", "#8b5cf6",
        ["network", "dns", "ebpf"]
    ),
}

# Mapowanie decoder.name na kategorie
DECODER_CATEGORIES = {
    "rootcheck": LOCATION_CATEGORIES["rootcheck"],
    "ossec": LogCategory(
        "ossec", "OSSEC/Wazuh", "info", "📡", "#0d9488",
        ["wazuh", "output"]
    ),
    "systemd": LogCategory(
        "systemd", "Systemd", "info", "⚡", "#64748b",
        ["system", "service"]
    ),
    "pam": LogCategory(
        "pam", "Authentication", "medium", "🔐", "#b45309",
        ["auth", "pam", "session"]
    ),
    "sudo": LogCategory(
        "sudo", "Privilege Escalation", "medium", "⬆️", "#c2410c",
        ["sudo", "privilege", "root"]
    ),
    "sca": LOCATION_CATEGORIES["sca"],
    "kernel": LogCategory(
        "network_traffic", "Ruch sieciowy", "info", "🌐", "#0ea5e9",
        ["network", "kernel", "firewall_log"]
    ),
}

# Kategorie/tagi uznawane za logi sieciowe
NETWORK_CATEGORY_NAMES = frozenset({
    "network_traffic", "firewall", "login_history", "network_flow", "netstat_ports", "dns_query",
})

# Grupy Wazuh -> nasze tagi
RULE_GROUP_TAGS = {
    "authentication_success": ["auth_success"],
    "authentication_failed": ["auth_failed", "security"],
    "syslog": ["syslog"],
    "pam": ["pam"],
    "sudo": ["sudo"],
    "ossec": ["wazuh"],
    "policy": ["policy"],
    "gdpr": ["gdpr", "compliance"],
    "hipaa": ["hipaa", "compliance"],
    "pci_dss": ["pci_dss", "compliance"],
}

# Wzorce w full_log do wykrywania typu (ostatni element = tag "network" jeśli True)
LOG_PATTERNS = {
    "df -P": ("filesystem", "Dysk/Filesystem", "info", "💾", "#0891b2", False),
    "last -n": ("login_history", "Historia logowań (IP)", "info", "👤", "#6366f1", True),
    "guest-ping": ("heartbeat", "Heartbeat", "info", "💓", "#22c55e", False),
    "Started Wazuh": ("wazuh_start", "Start Wazuh", "info", "✅", "#059669", False),
    "Agent started": ("agent_start", "Start agenta", "info", "✅", "#059669", False),
    "Manager started": ("manager_start", "Start managera", "info", "✅", "#059669", False),
    "session opened": ("session_open", "Sesja otwarta", "medium", "🔓", "#b45309", False),
    "session closed": ("session_close", "Sesja zamknięta", "info", "🔒", "#6b7280", False),
    "sudo": ("sudo_exec", "Użycie sudo", "medium", "⬆️", "#c2410c", False),
    "rootcheck scan": ("rootcheck", "Rootcheck", "info", "🔍", "#4a90d9", False),
    "CIS ": ("cis_benchmark", "CIS Benchmark", "medium", "🛡️", "#dc2626", False),
    "nft add": ("firewall", "Firewall (nftables)", "medium", "🔥", "#ea580c", True),
    "iptables": ("firewall", "Firewall", "medium", "🔥", "#ea580c", True),
    " SRC=": ("network_traffic", "Ruch sieciowy", "info", "🌐", "#0ea5e9", True),
    "PROTO=TCP": ("network_traffic", "Ruch sieciowy", "info", "🌐", "#0ea5e9", True),
    "PROTO=UDP": ("network_traffic", "Ruch sieciowy", "info", "🌐", "#0ea5e9", True),
}


def _get_decoder_name(entry: dict) -> Optional[str]:
    decoder = entry.get("decoder")
    if decoder is None:
        return None
    if isinstance(decoder, dict):
        name = decoder.get("name")
        return str(name) if name is not None and name != "" else None
    return None


def _get_program_name(entry: dict) -> Optional[str]:
    predecoder = entry.get("predecoder")
    if predecoder is None or not isinstance(predecoder, dict):
        return None
    name = predecoder.get("program_name")
    return str(name) if name is not None and name != "" else None


def _get_rule_level(entry: dict) -> int:
    rule = entry.get("rule")
    if not isinstance(rule, dict):
        return 3
    level = rule.get("level", 3)
    try:
        lv = int(level)
        return max(0, min(15, lv))
    except (TypeError, ValueError):
        return 3


def _get_rule_groups(entry: dict) -> list[str]:
    rule = entry.get("rule")
    if not isinstance(rule, dict):
        return []
    groups = rule.get("groups")
    if not isinstance(groups, list):
        return []
    return [str(g) for g in groups if g is not None]


def _get_location(entry: dict) -> Optional[str]:
    loc = entry.get("location")
    if loc is None or loc == "":
        return None
    try:
        return str(loc) if not isinstance(loc, dict) else None
    except (TypeError, ValueError):
        return None


def _pattern_match(full_log: str) -> Optional[tuple[LogCategory, bool]]:
    """Sprawdza wzorce w treści logu. Zwraca (kategoria, czy_log_sieciowy)."""
    if not full_log:
        return None
    full_log_lower = full_log.lower()
    # SRC= / PROTO= sprawdzamy przed innymi (bardziej specyficzne)
    for pattern, args in LOG_PATTERNS.items():
        if pattern.strip() and pattern.lower() in full_log_lower:
            is_net = args[5] if len(args) >= 6 else False
            cat = LogCategory(args[0], args[1], args[2], args[3], args[4], ["network"] if is_net else [])
            return (cat, is_net)
    return None


def categorize(entry: dict[str, Any]) -> LogCategory:
    """
    Inteligentnie kategoryzuje pojedynczy wpis logu.
    
    Priorytet: rule.description > location > decoder > predecoder > wzorce w full_log
    """
    if not isinstance(entry, dict):
        return LogCategory("unknown", "Inne", "info", "📄", "#9ca3af", ["uncategorized"])
    full_log = entry.get("full_log")
    full_log = str(full_log) if full_log is not None else ""
    location = _get_location(entry)
    decoder_name = _get_decoder_name(entry)
    program_name = _get_program_name(entry)
    rule_level = _get_rule_level(entry)
    rule_groups = _get_rule_groups(entry)
    
    # 0. Kernel + SRC/DST/PROTO = ruch sieciowy (priorytet nad journald)
    if decoder_name == "kernel" and full_log:
        if " SRC=" in full_log and (" DST=" in full_log or "PROTO=TCP" in full_log or "PROTO=UDP" in full_log):
            cat = DECODER_CATEGORIES["kernel"]
            tags = list(cat.tags)
            for g in rule_groups:
                if g in RULE_GROUP_TAGS:
                    tags.extend(RULE_GROUP_TAGS[g])
            return LogCategory(
                cat.name, cat.display_name,
                SEVERITY_MAP.get(rule_level, cat.severity),
                cat.icon, cat.color, list(dict.fromkeys(tags))
            )

    # 0b. JSON decoder + data.type (np. network_flow)
    data = entry.get("data")
    if isinstance(data, dict) and decoder_name == "json":
        dtype = data.get("type")
        if dtype and dtype in JSON_DECODER_TYPES:
            cat = JSON_DECODER_TYPES[dtype]
            tags = list(cat.tags)
            for g in rule_groups:
                if g in RULE_GROUP_TAGS:
                    tags.extend(RULE_GROUP_TAGS[g])
            return LogCategory(
                cat.name, cat.display_name,
                SEVERITY_MAP.get(rule_level, cat.severity),
                cat.icon, cat.color, list(dict.fromkeys(tags))
            )

    # 1. Location ma wysoki priorytet
    if location and location in LOCATION_CATEGORIES:
        cat = LOCATION_CATEGORIES[location]
        tags = list(cat.tags)
        for g in rule_groups:
            if g in RULE_GROUP_TAGS:
                tags.extend(RULE_GROUP_TAGS[g])
        return LogCategory(
            cat.name, cat.display_name,
            SEVERITY_MAP.get(rule_level, cat.severity),
            cat.icon, cat.color, list(dict.fromkeys(tags))
        )
    
    # 2. Decoder
    if decoder_name and decoder_name in DECODER_CATEGORIES:
        cat = DECODER_CATEGORIES[decoder_name]
        # sudo + nft/iptables w komendzie = firewall (log sieciowy)
        if decoder_name == "sudo" and ("nft " in full_log or "iptables" in full_log):
            cat = LogCategory("firewall", "Firewall (nftables)", "medium", "🔥", "#ea580c", ["network"])
        tags = list(cat.tags)
        for g in rule_groups:
            if g in RULE_GROUP_TAGS:
                tags.extend(RULE_GROUP_TAGS[g])
        return LogCategory(
            cat.name, cat.display_name,
            SEVERITY_MAP.get(rule_level, cat.severity),
            cat.icon, cat.color, list(dict.fromkeys(tags))
        )
    
    # 3. Wzorce w full_log
    pattern_result = _pattern_match(full_log)
    if pattern_result:
        pattern_cat, _ = pattern_result
        tags = list(pattern_cat.tags)
        for g in rule_groups:
            if g in RULE_GROUP_TAGS:
                tags.extend(RULE_GROUP_TAGS[g])
        return LogCategory(
            pattern_cat.name, pattern_cat.display_name,
            SEVERITY_MAP.get(rule_level, pattern_cat.severity),
            pattern_cat.icon, pattern_cat.color, list(dict.fromkeys(tags))
        )
    
    # 4. Program name z predecoder
    if program_name:
        prog_lower = program_name.lower()
        if "sudo" in prog_lower:
            return DECODER_CATEGORIES["sudo"]
        if "systemd" in prog_lower:
            return DECODER_CATEGORIES["systemd"]
        if "pam" in prog_lower or "polkit" in prog_lower:
            return DECODER_CATEGORIES["pam"]
    
    # 5. Domyślna kategoria
    return LogCategory(
        "unknown", "Inne", SEVERITY_MAP.get(rule_level, "info"),
        "📄", "#9ca3af", ["uncategorized"]
    )

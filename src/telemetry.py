"""
Telemetria: agregacje czasowe i dane do wykresów.
"""

import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from . import network_analytics as na


def parse_entry_timestamp(entry: dict) -> Optional[datetime]:
    """Parsuje timestamp z wpisu (ISO lub unix). Eksportowane do filtrów czasowych."""
    return _parse_ts(entry)


def _parse_ts(entry: dict) -> Optional[datetime]:
    """Parsuje timestamp z wpisu (ISO lub unix)."""
    ts = entry.get("timestamp") or entry.get("@timestamp")
    if ts is None:
        data = entry.get("data")
        if isinstance(data, dict) and "timestamp" in data:
            ts = data["timestamp"]
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OSError):
            return None
    if isinstance(ts, str):
        try:
            ts = ts.strip()
            if not ts:
                return None
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            # Normalizuj strefę na końcu: +0100/-0100 → +01:00/-01:00
            m = re.search(r"([+-])(\d{2}):?(\d{2})$", ts)
            if m:
                ts = ts[: m.start()] + m.group(1) + m.group(2) + ":" + m.group(3)
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    return None


def compute_telemetry(
    entries: list[dict],
    bucket_minutes: int = 5,
    *,
    hours: Optional[float] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict[str, Any]:
    """
    Oblicza telemetrię: serie czasowe, rozkłady.
    bucket_minutes: rozmiar przedziału czasowego (np. 5 = co 5 minut).
    hours: zakres w godzinach (domyślnie 24); używane gdy brak start/end.
    start, end: jawny zakres czasowy (UTC); nadpisuje hours.
    """
    now = datetime.now(timezone.utc)
    if start is not None and end is not None:
        range_start = start.astimezone(timezone.utc) if start.tzinfo else start.replace(tzinfo=timezone.utc)
        range_end = end.astimezone(timezone.utc) if end.tzinfo else end.replace(tzinfo=timezone.utc)
    else:
        h = 24.0 if hours is None else max(0.25, min(168, float(hours)))  # 0.25h–7d
        range_end = now
        range_start = now - timedelta(hours=h)

    span_sec = (range_end - range_start).total_seconds()
    bucket_sec = max(60, bucket_minutes * 60)
    n_buckets = max(1, min(500, int(span_sec / bucket_sec)))
    bucket_sec = span_sec / n_buckets

    total_buckets: list[int] = [0] * n_buckets
    network_buckets: list[int] = [0] * n_buckets
    by_category: dict[str, int] = defaultdict(int)
    by_severity: dict[str, int] = defaultdict(int)
    network_by_type: dict[str, int] = defaultdict(int)

    for e in entries:
        if not isinstance(e, dict):
            continue
        ts = _parse_ts(e)
        cat = e.get("_category") or {}
        cname = cat.get("display_name", "Inne")
        sev = cat.get("severity", "info")
        by_category[cname] += 1
        by_severity[sev] += 1

        if na.is_network_log(e):
            st = na.network_subtype(e)
            network_by_type[st] += 1

        if ts:
            try:
                ts_utc = ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
                if range_start <= ts_utc <= range_end:
                    age_sec = (ts_utc - range_start).total_seconds()
                    idx = min(int(age_sec / bucket_sec), n_buckets - 1)
                    if 0 <= idx < n_buckets:
                        total_buckets[idx] += 1
                        if na.is_network_log(e):
                            network_buckets[idx] += 1
            except Exception:
                pass

    # Etykiety: od najstarszego do najnowszego
    labels_final = []
    for i in range(n_buckets):
        t = range_start + timedelta(seconds=bucket_sec * i)
        labels_final.append(t.strftime("%d %H:%M") if span_sec > 86400 else t.strftime("%H:%M"))
    total_series = total_buckets
    network_series = network_buckets

    type_labels = {
        "traffic": "Ruch sieciowy", "firewall": "Firewall", "logins": "Logowania (IP)",
        "flow": "Przepływ (eBPF)", "ports": "Porty nasłuchujące", "dns": "Zapytania DNS",
        "other": "Inne"
    }
    network_by_type_display = {type_labels.get(k, k): v for k, v in network_by_type.items()}

    return {
        "time_labels": labels_final,
        "time_total": total_series,
        "time_network": network_series,
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "network_by_type": dict(network_by_type_display),
    }

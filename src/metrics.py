"""
Metryki dla Prometheusa i zakładki Serwis.

Liczniki: błędy odczytu pliku, ostatni czas odczytu.
Wartości bieżące (gauges) ustawiane przy generowaniu /metrics (wpisy w pamięci, w DB, alerty).
"""

import time
from typing import Optional

# Licznik błędów odczytu archiwum (z LogProcessora)
_read_errors_total: int = 0

# Ostatni udany odczyt (timestamp Unix)
_last_read_timestamp: Optional[float] = None


def increment_read_errors() -> None:
    global _read_errors_total
    _read_errors_total += 1


def set_last_read_time(timestamp: Optional[float] = None) -> None:
    """Ustawia czas ostatniego udanego odczytu (domyślnie: now)."""
    global _last_read_timestamp
    _last_read_timestamp = timestamp if timestamp is not None else time.time()


def get_last_read_timestamp() -> Optional[float]:
    return _last_read_timestamp


def get_read_errors_total() -> int:
    return _read_errors_total


def render_prometheus(
    *,
    entries_in_memory: int = 0,
    entries_in_db: Optional[int] = None,
    alerts_critical: int = 0,
    alerts_high: int = 0,
) -> str:
    """Generuje tekst w formacie Prometheus (exposition format)."""
    lines = [
        "# HELP networkc_entries_in_memory Liczba wpisów w buforze pamięci",
        "# TYPE networkc_entries_in_memory gauge",
        f"networkc_entries_in_memory {entries_in_memory}",
        "# HELP networkc_read_errors_total Błędy odczytu pliku archiwum",
        "# TYPE networkc_read_errors_total counter",
        f"networkc_read_errors_total {get_read_errors_total()}",
        "# HELP networkc_alerts_critical_total Liczba alertów critical w oknie",
        "# TYPE networkc_alerts_critical_total gauge",
        f"networkc_alerts_critical_total {alerts_critical}",
        "# HELP networkc_alerts_high_total Liczba alertów high w oknie",
        "# TYPE networkc_alerts_high_total gauge",
        f"networkc_alerts_high_total {alerts_high}",
    ]
    if entries_in_db is not None:
        lines.extend([
            "# HELP networkc_entries_in_db Liczba wpisów w bazie SQLite",
            "# TYPE networkc_entries_in_db gauge",
            f"networkc_entries_in_db {entries_in_db}",
        ])
    ts = get_last_read_timestamp()
    if ts is not None:
        lines.extend([
            "# HELP networkc_last_read_timestamp_seconds Unix timestamp ostatniego odczytu pliku",
            "# TYPE networkc_last_read_timestamp_seconds gauge",
            f"networkc_last_read_timestamp_seconds {ts:.2f}",
        ])
    return "\n".join(lines) + "\n"

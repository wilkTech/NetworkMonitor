"""Konfiguracja aplikacji - plik YAML/JSON + zmienne środowiskowe (env nadpisuje)."""

import json
import os
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent

# Wersja aplikacji (do health / Serwis)
APP_VERSION = os.getenv("APP_VERSION", "0.2.0")

# Ładowanie z pliku konfiguracyjnego (opcjonalnie)
_CONFIG: dict = {}
_CONFIG_FILE = os.getenv("CONFIG_FILE", "").strip()
if _CONFIG_FILE:
    path = Path(_CONFIG_FILE)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                if path.suffix.lower() in (".yaml", ".yml"):
                    try:
                        import yaml
                        _CONFIG = yaml.safe_load(f) or {}
                    except ImportError:
                        _CONFIG = {}
                else:
                    _CONFIG = json.load(f)
        except Exception:
            _CONFIG = {}


def _get(key: str, env_key: str, default: str) -> str:
    """Wartość: z pliku konfiguracyjnego, nadpisana przez zmienną środowiskową."""
    val = _CONFIG.get(key, default)
    return os.getenv(env_key, str(val) if val is not None else default)


def _env_int(key: str, default: int) -> int:
    """Odczytuje int ze zmiennej środowiskowej; przy błędzie zwraca default."""
    file_val = _CONFIG.get(key.lower()) or _CONFIG.get(key.replace("_", "-").lower())
    if file_val is not None:
        try:
            default = int(file_val)
        except (TypeError, ValueError):
            pass
    try:
        return int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(key: str, default: float) -> float:
    """Odczytuje float ze zmiennej środowiskowej; przy błędzie zwraca default."""
    file_val = _CONFIG.get(key.lower()) or _CONFIG.get(key.replace("_", "-").lower())
    if file_val is not None:
        try:
            default = float(file_val)
        except (TypeError, ValueError):
            pass
    try:
        return float(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        return default


# Ścieżka do archiwum logów Wazuh
ARCHIVES_PATH = _get("archives_path", "OSSEC_ARCHIVES_PATH", "/var/ossec/logs/archives/archives.json")
# Gdy plik nie istnieje: interwał ponawiania (sekundy) i max prób (0 = bez limitu)
ARCHIVES_WAIT_SECONDS = _env_int("ARCHIVES_WAIT_SECONDS", 10)
ARCHIVES_WAIT_MAX_RETRIES = _env_int("ARCHIVES_WAIT_MAX_RETRIES", 0)

# Port serwera webowego
WEB_PORT = _env_int("WEB_PORT", 8000)

# Host serwera
WEB_HOST = _get("web_host", "WEB_HOST", "0.0.0.0")

# Maksymalna liczba logów przechowywanych w pamięci
MAX_LOGS_IN_MEMORY = _env_int("MAX_LOGS_IN_MEMORY", 5000)

# Interwał sprawdzania nowych wpisów (sekundy)
TAIL_POLL_INTERVAL = _env_float("TAIL_POLL_INTERVAL", 0.5)

# Plik do zapisu logów aplikacji (pełne logowanie działania)
LOG_FILE = _get("log_file", "LOG_FILE", str(_PROJECT_ROOT / "logs" / "app.log"))

# Poziom logowania aplikacji: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL = _get("log_level", "LOG_LEVEL", "INFO").upper()

# CORS: rozdzielone przecinkami originy (puste = wyłączone). * = zezwól na wszystko
CORS_ORIGINS = _get("cors_origins", "CORS_ORIGINS", "").strip()

# Maksymalna liczba wyników wyszukiwania pełnotekstowego
SEARCH_MAX_RESULTS = _env_int("SEARCH_MAX_RESULTS", 2000)

# Domyślny zakres czasu telemetrii (godziny)
TELEMETRY_HOURS = _env_int("TELEMETRY_HOURS", 24)

# Endpoint odświeżania bufora (reload z pliku) – włączony domyślnie
_enable_refresh = _CONFIG.get("enable_refresh_endpoint", True)
ENABLE_REFRESH_ENDPOINT = os.getenv("ENABLE_REFRESH_ENDPOINT", str(_enable_refresh)).lower() in ("1", "true", "yes")

# Okno czasowe dla alertów (minuty) – ile ostatnich minut sprawdzać pod kątem critical/high
ALERTS_WINDOW_MINUTES = _env_int("ALERTS_WINDOW_MINUTES", 60)

# Baza danych SQLite (domyślnie włączona; szybsze wyszukiwanie, retencja czasowa)
_enable_db = _CONFIG.get("enable_db", True)
ENABLE_DB = os.getenv("ENABLE_DB", "1" if _enable_db else "0").strip().lower() in ("1", "true", "yes")
DB_PATH = _get("db_path", "DB_PATH", str(_PROJECT_ROOT / "data" / "logs.db"))
DB_RETENTION_DAYS = _env_int("DB_RETENTION_DAYS", 7)
# Batch insert: zapis do DB co N wpisów (0 = pojedynczo)
DB_BATCH_SIZE = _env_int("DB_BATCH_SIZE", 50)
# Okresowy flush bufora do DB co N sekund (0 = tylko po batch_size); wpisy trafiają do bazy nawet przy małym ruchu
DB_FLUSH_INTERVAL_SECONDS = _env_int("DB_FLUSH_INTERVAL_SECONDS", 5)

# Walidacja ścieżki
def get_archives_path() -> Path:
    path = Path(ARCHIVES_PATH)
    if not path.exists():
        raise FileNotFoundError(f"Plik archiwum nie istnieje: {ARCHIVES_PATH}")
    return path


def wait_for_archives_path() -> Path:
    """
    Czeka na pojawienie się pliku archiwum (np. Wazuh jeszcze nie wystartował).
    Loguje ostrzeżenie i ponawia co ARCHIVES_WAIT_SECONDS. ARCHIVES_WAIT_MAX_RETRIES=0 = bez limitu.
    """
    path = Path(ARCHIVES_PATH)
    retries = 0
    while not path.exists():
        if ARCHIVES_WAIT_MAX_RETRIES and retries >= ARCHIVES_WAIT_MAX_RETRIES:
            raise FileNotFoundError(
                f"Plik archiwum nie pojawił się po {ARCHIVES_WAIT_MAX_RETRIES} próbach: {ARCHIVES_PATH}"
            )
        retries += 1
        import logging as _log
        _log.getLogger(__name__).warning(
            "Plik archiwum nie istnieje (próba %s), ponowię za %s s: %s",
            retries, ARCHIVES_WAIT_SECONDS, ARCHIVES_PATH,
        )
        time.sleep(ARCHIVES_WAIT_SECONDS)
    return path

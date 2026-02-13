#!/usr/bin/env python3
"""
Uruchomienie aplikacji OSSEC/Wazuh Log Viewer.

Użycie:
    python main.py
    # lub
    OSSEC_ARCHIVES_PATH=/ścieżka/do/archives.json python main.py
"""

import logging
import sys
from pathlib import Path

import uvicorn

from config import (
    LOG_FILE,
    LOG_LEVEL,
    MAX_LOGS_IN_MEMORY,
    TAIL_POLL_INTERVAL,
    WEB_HOST,
    WEB_PORT,
    wait_for_archives_path,
)
from src.web_app import create_app

# Format logów
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Utworzenie katalogu na logi
log_path = Path(LOG_FILE)
log_path.parent.mkdir(parents=True, exist_ok=True)

# Konfiguracja: konsola + plik
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(formatter)
root_logger.addHandler(file_handler)

if __name__ == "__main__":
    try:
        archives_path = wait_for_archives_path()
    except FileNotFoundError as e:
        print(f"Błąd: {e}", file=sys.stderr)
        sys.exit(1)

    app = create_app(archives_path=archives_path, max_logs=MAX_LOGS_IN_MEMORY, poll_interval=TAIL_POLL_INTERVAL)

    root_logger.info("Serwer startuje na http://%s:%s", WEB_HOST, WEB_PORT)
    root_logger.info("Archiwum logów: %s", archives_path)
    root_logger.info("Logi aplikacji zapisywane do: %s", LOG_FILE)
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT)

"""
Procesor logów Wazuh w czasie rzeczywistym.

Śledzi plik archives.json (tail -f style) i kategoryzuje każdy wpis.

Źródło danych: plik JSON (archives.json), każda linia lub blok to jeden obiekt JSON
(w formacie Wazuh: timestamp, decoder, rule, full_log, agent, data, location, …).
Walidacja: akceptowane są tylko obiekty (dict); nie-dict są pomijane; błędy
kategoryzacji nie odrzucają wpisu – wpis dostaje _category "unknown".
Niepełny JSON na granicy odczytu jest buforowany do następnego poll().

Wykrywanie rotacji/truncate: gdy plik zostanie obcięty lub zastąpiony (nowy inode),
pozycja jest resetowana, żeby program ponownie zaciągał dane z aktualnego pliku.
"""

import json
import logging
import os
import time
from collections import deque
from pathlib import Path
from typing import Callable, Optional

from .categorizer import categorize, LogCategory

logger = logging.getLogger(__name__)


class LogProcessor:
    """Przetwarza logi w czasie rzeczywistym i utrzymuje bufor ostatnich wpisów."""

    # Maks. rozmiar bufora niepełnego JSON; przy przekroczeniu bufor jest czyszczony (unikamy zawieszenia na jednym uciętym obiekcie)
    DEFAULT_MAX_READ_BUFFER_BYTES = 512 * 1024
    # Po tylu kolejnych odczytach bez nowych wpisów (przy niepustym buforze) wymuszamy resync do końca pliku
    STALE_BUFFER_POLLS = 24  # ~12 s przy poll_interval=0.5

    def __init__(
        self,
        archives_path: Path,
        max_logs: int = 5000,
        poll_interval: float = 0.5,
        on_new_entry: Optional[Callable] = None,
        on_read_error: Optional[Callable[[], None]] = None,
        max_read_buffer_bytes: Optional[int] = None,
    ):
        self.archives_path = Path(archives_path)
        self.max_logs = max_logs
        self.poll_interval = poll_interval
        self.on_new_entry = on_new_entry
        self.on_read_error = on_read_error
        self.max_read_buffer_bytes = max_read_buffer_bytes or self.DEFAULT_MAX_READ_BUFFER_BYTES

        self._entries: deque = deque(maxlen=max_logs)
        self._file_position = 0
        self._running = False
        # Bufor na niepełny JSON na granicy odczytu (obiekt wieloliniowy)
        self._read_buffer = ""
        # Inode ostatnio czytanego pliku – przy rotacji (nowy plik pod tą samą ścieżką) resetujemy pozycję
        self._last_inode: Optional[int] = None
        # Liczba kolejnych polli bez nowych wpisów przy niepustym buforze – wymusza resync przy „zatkaniu”
        self._polls_no_progress: int = 0

    @property
    def entries(self) -> list[dict]:
        """Ostatnie wpisy (najstarsze first)."""
        return list(self._entries)

    def _parse_single(self, obj: dict) -> dict:
        """Kategoryzuje pojedynczy wpis."""
        if not isinstance(obj, dict):
            raise ValueError(f"Oczekiwano dict, otrzymano {type(obj).__name__}")
        try:
            category = categorize(obj)
            obj["_category"] = {
                "name": category.name,
                "display_name": category.display_name,
                "severity": category.severity,
                "icon": category.icon,
                "color": category.color,
                "tags": list(category.tags) if category.tags else [],
            }
        except Exception as e:
            logger.exception("Błąd kategoryzacji: %s", e)
            obj["_category"] = {
                "name": "unknown",
                "display_name": "Inne",
                "severity": "info",
                "icon": "📄",
                "color": "#9ca3af",
                "tags": ["uncategorized", "parse_error"],
            }
        return obj

    def _read_json_lines(self, text: str) -> tuple[list[dict], str]:
        """
        Parsuje tekst – JSON może zajmować wiele linii (full_log z \\n).
        Używa raw_decode; zwraca (lista wpisów, nieparsowany ogon bufora).
        """
        entries = []
        buffer = text.lstrip()
        decoder = json.JSONDecoder()
        while buffer:
            try:
                obj, idx = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                break
            if isinstance(obj, dict):
                try:
                    entries.append(self._parse_single(obj))
                except Exception as ex:
                    logger.warning("Pominięto wpis (błąd przetwarzania): %s", ex)
            else:
                logger.debug("Pominięto wpis (nie jest obiektem): %s", type(obj).__name__)
            buffer = buffer[idx:].lstrip()
        return entries, buffer

    def _effective_archives_path(self) -> Optional[Path]:
        """Ścieżka do aktualnego pliku: resolve() gdy plik istnieje (obsługa symlinków i rotacji)."""
        if not self.archives_path.exists():
            return None
        try:
            return self.archives_path.resolve()
        except OSError:
            return self.archives_path

    def _read_new_lines(self) -> list[dict]:
        """Odczytuje nowe linie od ostatniej pozycji w pliku. Buforuje niepełny JSON.
        Wykrywa rotację/truncate: gdy plik się zmienił (inode) lub pozycja > rozmiar, resetuje śledzenie.
        Zawsze otwiera plik po ścieżce (resolve przy symlinku), żeby po rotacji Wazuh czytać aktualny plik.
        """
        path = self._effective_archives_path()
        if path is None:
            return []

        new_entries = []
        try:
            try:
                stat_info = path.stat()
                current_inode = stat_info.st_ino
                current_size = stat_info.st_size
            except OSError:
                current_inode = None
                current_size = 0

            # Rotacja: pod tą samą ścieżką jest inny plik (nowy inode)
            if self._last_inode is not None and current_inode is not None and current_inode != self._last_inode:
                logger.warning(
                    "Wykryto rotację pliku archiwum (inode %s -> %s), reset śledzenia",
                    self._last_inode, current_inode,
                )
                self._file_position = 0
                self._read_buffer = ""
                self._polls_no_progress = 0
            # Truncate lub nowy pusty plik: zapisana pozycja jest za końcem pliku
            elif self._file_position > current_size:
                logger.warning(
                    "Pozycja pliku (%s) za końcem (rozmiar %s), reset śledzenia",
                    self._file_position, current_size,
                )
                self._file_position = 0
                self._read_buffer = ""
                self._polls_no_progress = 0

            with open(path, "r", encoding="utf-8", errors="replace") as f:
                if self._file_position > 0:
                    try:
                        f.seek(self._file_position)
                    except OSError:
                        self._file_position = 0

                new_content = f.read()
                self._file_position = f.tell()
                self._last_inode = current_inode
                combined = self._read_buffer + new_content
                new_entries, self._read_buffer = self._read_json_lines(combined)

            # Niepełny JSON nie może rosnąć w nieskończoność (np. ucięty wpis na końcu pliku)
            if len(self._read_buffer) > self.max_read_buffer_bytes:
                logger.warning(
                    "Bufor niepełnego JSON przekroczył %s B (%s B), reset bufora i resync do końca pliku",
                    self.max_read_buffer_bytes, len(self._read_buffer),
                )
                self._read_buffer = ""
                self._file_position = current_size  # resync: następny odczyt tylko nowe dane, bez ponownego wczytywania ogona
                self._polls_no_progress = 0
            else:
                # Brak postępu: od wielu polli nie ma nowych wpisów, a bufor nie jest pusty – wymuszamy resync
                if new_entries:
                    self._polls_no_progress = 0
                elif self._read_buffer:
                    self._polls_no_progress += 1
                    if self._polls_no_progress >= self.STALE_BUFFER_POLLS:
                        logger.warning(
                            "Brak nowych wpisów od %s polli (bufor %s B), resync do końca pliku",
                            self._polls_no_progress, len(self._read_buffer),
                        )
                        self._read_buffer = ""
                        self._file_position = current_size
                        self._polls_no_progress = 0
                else:
                    self._polls_no_progress = 0
        except (IOError, OSError) as e:
            logger.error("Błąd odczytu pliku: %s", e)
            if self.on_read_error:
                try:
                    self.on_read_error()
                except Exception:
                    pass

        return new_entries

    def _read_tail_lines(self, n: int) -> tuple[list[dict], str]:
        """Czyta tylko ostatnie n linii z pliku (szybszy start przy dużych plikach)."""
        path = self._effective_archives_path()
        if path is None or n <= 0:
            return [], ""
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                # Szacunkowo ~1KB na linię (logi bywają długie); czytaj od pozycji na n linii
                chunk_size = min(size, max(2 * 1024 * 1024, n * 1000))
                start = max(0, size - chunk_size)
                f.seek(start)
                if start > 0:
                    f.readline()  # prawdopodobnie ucięta linia – pomiń
                lines = []
                for line in f:
                    lines.append(line.decode("utf-8", errors="replace"))
                lines = lines[-n:]  # ostatnie n linii (może być fragment wieloliniowego JSON)
        except (IOError, OSError) as e:
            logger.error("Błąd odczytu tail: %s", e)
            if self.on_read_error:
                try:
                    self.on_read_error()
                except Exception:
                    pass
            return [], ""
        text = "".join(lines)
        entries, leftover = self._read_json_lines(text)
        return entries, leftover

    def load_initial(self) -> int:
        """
        Ładuje ostatnie max_logs wpisów (szybki start bez czytania całego pliku).
        Ustawia _file_position na koniec pliku; niepełny JSON trafia do _read_buffer.
        """
        entries, self._read_buffer = self._read_tail_lines(self.max_logs)
        for e in entries:
            self._entries.append(e)
            if self.on_new_entry:
                try:
                    self.on_new_entry(e)
                except Exception as ex:
                    logger.exception("Błąd w on_new_entry (load_initial): %s", ex)
        path = self._effective_archives_path()
        if path is not None:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, 2)
                    self._file_position = f.tell()
                try:
                    self._last_inode = path.stat().st_ino
                except OSError:
                    self._last_inode = None
            except (IOError, OSError):
                self._file_position = 0
                self._last_inode = None
        else:
            self._file_position = 0
            self._last_inode = None
        return len(entries)

    def poll(self) -> list[dict]:
        """
        Sprawdza nowe wpisy i zwraca listę nowo dodanych.
        """
        new_entries = self._read_new_lines()
        for e in new_entries:
            self._entries.append(e)
            if self.on_new_entry:
                try:
                    self.on_new_entry(e)
                except Exception as ex:
                    logger.exception("Błąd w on_new_entry: %s", ex)
        return new_entries

    def run_tail(self):
        """Pętla tail - niekończące się śledzenie pliku."""
        self._running = True
        self.load_initial()
        logger.info("Załadowano %d wpisów, śledzę plik...", len(self._entries))
        while self._running:
            self.poll()
            time.sleep(self.poll_interval)

    def stop(self):
        """Zatrzymuje pętlę tail."""
        self._running = False

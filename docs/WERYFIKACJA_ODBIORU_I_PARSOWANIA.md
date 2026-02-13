# Weryfikacja przychodzących danych i parsowania

## 1. Źródło danych

| Element | Wartość |
|--------|---------|
| Plik | `config.ARCHIVES_PATH` (domyślnie `/var/ossec/logs/archives/archives.json`) |
| Zmienna środowiskowa | `OSSEC_ARCHIVES_PATH` |
| Format | JSON – każdy wpis to jeden obiekt (może zajmować wiele linii przez `\n` w `full_log`) |
| Odczyt | Plik tekstowy, UTF-8, `errors="replace"` przy błędach kodowania |

Walidacja ścieżki przy starcie: `config.get_archives_path()` – rzuca `FileNotFoundError`, jeśli plik nie istnieje.

---

## 2. Przepływ odbioru

1. **Start** – `load_initial()`: czyta ostatnie `max_logs` linii (`_read_tail_lines`), parsuje, ustawia `_file_position` na koniec pliku. Niepełny JSON na końcu trafia do `_read_buffer`.
2. **Poll** (co ~0.3–0.5 s): `_read_new_lines()` – odczyt od `_file_position` do EOF, dopisanie do `_read_buffer`, parsowanie, zapis ogona z powrotem do `_read_buffer`, `_file_position = f.tell()`.

### 2.1. Rotacja / truncate pliku

Gdy Wazuh rotuje logi (np. `archives.json` → nowy plik pod tą samą ścieżką) lub plik zostanie obcięty, zapisana `_file_position` przestaje być poprawna i program przestaje „widzieć” nowe dane. W `_read_new_lines()`:

- **Inode**: jeśli inode pliku się zmienił (ten sam path, inny plik), uznajemy rotację → reset `_file_position = 0`, `_read_buffer = ""`, log ostrzeżenia.
- **Pozycja > rozmiar**: jeśli `_file_position > current_size`, plik został obcięty lub zastąpiony mniejszym → ten sam reset.

Dzięki temu po rotacji/truncate następny poll czyta od początku aktualnego pliku i zaciąganie danych wznawia się.

---

## 3. Parsowanie JSON

- **Metoda**: `json.JSONDecoder().raw_decode()` – umożliwia wieloliniowy JSON i wiele obiektów w jednym bloku.
- **Walidacja wejścia**:
  - Tylko obiekty (`isinstance(obj, dict)`) są przetwarzane; listy/stringi/liczby są pomijane (log debug).
  - Błąd parsowania (`JSONDecodeError`) – przerywa pętlę, reszta bufora zostaje w `_read_buffer` do następnego odczytu (nie tracimy danych).
- **Walidacja pojedynczego wpisu** (`_parse_single`):
  - Wymagany typ: `dict`; inaczej `ValueError`.
  - Kategoryzacja w try/except – przy wyjątku wpis dostaje `_category`: `unknown`, `parse_error` w tagach; wpis nie jest odrzucany.

---

## 4. Oczekiwana struktura wpisu (Wazuh)

Używane pola w aplikacji (wszystkie opcjonalne z punktu widzenia parsowania):

| Pole | Typ | Użycie |
|------|-----|--------|
| `timestamp` | str | Wyświetlanie, sortowanie |
| `decoder` | dict | `decoder.name` → kategoryzacja |
| `rule` | dict | `level`, `groups`, `description` → severity, tagi |
| `full_log` | str | Kategoryzacja (wzorce), metadane sieci (SRC/DST/PROTO/SPT/DPT/IN) |
| `agent` | dict/str | `name`, `id` – filtry, statystyki |
| `data` | dict | `type` (network_flow, dns_query), IP, porty, query |
| `location` | str | Kategoryzacja (rootcheck, journald, sca, …) |
| `predecoder` | dict | `program_name` → kategoryzacja |

Brak wymaganych pól – wpis bez `decoder`/`rule`/`full_log` trafia do kategorii „Inne” lub dopasowania po wzorcach.

---

## 5. Parsowanie metadanych sieciowych

- **Kernel (full_log)**: regex w `network_analytics.parse_network_meta()` – SRC=, DST=, PROTO=, SPT=, DPT=, IN=; adresy ograniczone do 64 znaków; porty jako `int` w try/except.
- **eBPF (data)**: `parse_network_meta_from_entry()` – dla `data.type == "network_flow"` (src_ip, dst_ip, protocol, porty, bytes) i `data.type == "dns_query"` (query, qtype); fallback na `full_log` jeśli brak `data` lub nie rozpoznany typ.

---

## 6. Wprowadzone poprawki

- **Bufor niepełnego JSON**: Wcześniej przy obiekcie JSON rozciągającym się na granicy dwóch odczytów (poll) nieparsowalna reszta była tracona, a `_file_position` ustawiane na koniec pliku. Obecnie:
  - `_read_buffer` przechowuje ogon po parsowaniu.
  - Przy każdym odczycie: `combined = _read_buffer + new_content`; po parsowaniu `_read_buffer = leftover`.
  - `_read_json_lines` zwraca `(entries, leftover)`.
  - W `load_initial` wynik tail też ustawia `_read_buffer`, więc niepełny obiekt na końcu pliku przy starcie nie jest gubiony.

---

## 7. Plik z zewnątrz

Plik **„Struktura implementacji odbioru dan.txt”** (ścieżka Windows podana przez użytkownika) nie znajduje się w repozytorium. Weryfikacja oparta jest wyłącznie na kodzie w `src/log_processor.py`, `src/categorizer.py`, `src/network_analytics.py` oraz `config.py`.

---

## 8. Testy automatyczne (weryfikacja parsowania)

W katalogu `tests/` znajduje się plik `test_parsing.py` – testy jednostkowe sprawdzające m.in.:

- **LogProcessor**: parsowanie pojedynczego i wielu obiektów JSON, wieloliniowy `full_log`, niepełny JSON (ogon w buforze), pomijanie nie-dict; wymagany typ `dict` w `_parse_single`.
- **Categorizer**: pusty wpis, `decoder.name` (dict/string), `rule.level` (string/float), `rule.groups`, priorytet `location`, wzorce w `full_log`, `data.type` (network_flow, dns_query), agent jako dict lub string.
- **Network analytics**: wyciąganie SRC/DST/PROTO/SPT/DPT/IN z `full_log`; `network_flow` i `dns_query` z `data`; fallback na `full_log`; ograniczenie długości adresów.
- **Telemetria**: timestamp jako ISO, unix (int/float), `@timestamp`, `data.timestamp`; brak/nieprawidłowy → `None`.
- **API**: `_parse_time_param` (pusty, unix, ISO, nieprawidłowy); `_entry_in_time_range`; `_entry_matches_search` (pusty q = wszystkie, szukanie w full_log).
- **Config**: poprawne typy i domyślne wartości; nieprawidłowe zmienne liczbowe (np. `WEB_PORT=abc`) są odporne – używane są funkcje `_env_int`/`_env_float` z fallbackiem na domyślne wartości.

Uruchomienie: `python -m pytest tests/test_parsing.py -v` (wymaga: `pip install pytest`).

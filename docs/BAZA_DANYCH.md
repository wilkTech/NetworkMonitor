# Baza danych – analiza i projekt

## Cel

Wdrożenie bazy danych ma na celu:

- **Szybsze wyszukiwanie i filtry** – indeksy zamiast skanowania listy w pamięci.
- **Większy zakres danych** – przechowywanie znacznie więcej niż 5000 wpisów (konfigurowalna retencja).
- **Paginacja po stronie serwera** – `offset`/`limit` bez ładowania całego zestawu do pamięci.
- **Pełnotekstowe wyszukiwanie** – efektywne zapytania po treści logów (FTS).
- **Stabilność** – dane przetrwają restart aplikacji (opcjonalnie).

---

## Obecny stan

- Źródło: plik `archives.json` (Wazuh), odczyt w stylu tail.
- Bufor: `deque` w pamięci, max 5000 wpisów (`MAX_LOGS_IN_MEMORY`).
- Filtry (kategoria, severity, agent, `q`, zakres czasu) i statystyki – zawsze na pełnej liście w pamięci.
- Brak trwałości: po restarcie bufor jest pusty do ponownego odczytu pliku.

---

## Wybór technologii: SQLite

| Opcja | Zalety | Wady |
|-------|--------|------|
| **SQLite** | Brak osobnego serwera, jeden plik, FTS5, indeksy, wystarczające dla 100k–1M+ wierszy | Jedna instancja zapisu (wystarczająca dla jednego viewer-a) |
| PostgreSQL | Zaawansowane zapytania, skalowanie | Wymaga serwera, większa złożoność wdrożenia |
| Elasticsearch | Świetne full-text, agregacje | Ciężki stack, nadmiarowy dla małych/średnich instalacji |

**Rekomendacja:** SQLite z opcjonalnym włączeniem przez konfigurację. Domyślnie można zostawić tryb „tylko pamięć” (jak dziś), a baza włącza się np. zmienną `ENABLE_DB=1` lub `DB_PATH=...`.

---

## Schemat (SQLite)

### Tabela główna `log_entries`

Przechowuje zdenormalizowane pola do filtrów i pełny dokument (JSON):

| Kolumna | Typ | Opis |
|---------|-----|------|
| `id` | INTEGER PRIMARY KEY | Auto-increment |
| `ts` | REAL | Unix timestamp (UTC) do indeksów i zakresów czasowych |
| `ts_iso` | TEXT | Oryginalny string (timestamp z Wazuh) |
| `category_name` | TEXT | np. "Ruch sieciowy", "Firewall" |
| `category_key` | TEXT | Klucz wewnętrzny kategorii |
| `severity` | TEXT | info, low, medium, high, critical |
| `agent_name` | TEXT | Wyciągnięta nazwa/ID agenta |
| `rule_id` | TEXT | rule.id |
| `rule_description` | TEXT | rule.description (skrócony do ~500 znaków) |
| `full_log` | TEXT | Pełna linia logu (do wyświetlania i FTS) |
| `raw_json` | TEXT | Cały wpis jako JSON (do odtworzenia obiektu z _category) |

Opcjonalnie (dla szybszych filtrów w zakładce „Logi sieciowe”):

| Kolumna | Typ | Opis |
|---------|-----|------|
| `network_src` | TEXT | IP źródłowy |
| `network_dst` | TEXT | IP docelowy |
| `network_proto` | TEXT | TCP, UDP, … |
| `network_dport` | INTEGER | Port docelowy |
| `network_query` | TEXT | Zapytanie DNS |

### Indeksy

- `(ts DESC)` – lista „najnowsze first”, zakresy czasowe.
- `(category_name)`, `(severity)`, `(agent_name)` – filtry.
- `(network_src, network_dst)` – opcjonalnie dla zakładki sieci.
- **FTS5** – tabela wirtualna `log_entries_fts` na `full_log` (+ ewentualnie rule_description) dla parametru `q`.

### Retencja

- **Czas trzymania wpisów**: konfigurowalna liczba dni (`DB_RETENTION_DAYS`, domyślnie 7). Wpisy starsze niż N dni są usuwane **dla wszystkich agentów/hostów**. Przy każdym zapisie sprawdzane jest `ts < (now - retention_days)` i takie rekordy są usuwane.

---

## Przepływ danych

1. **Zapis**
   - Procesor po przetworzeniu wpisu (po kategoryzacji) zapisuje go do SQLite (jeśli `ENABLE_DB`) oraz dodaje do bufora w pamięci (np. ostatnie 1000–5000 dla SSE i szybkiej listy „ostatnie N”).
2. **Odczyt**
   - **GET /api/logs** – zapytanie do DB z filtrami (category, severity, agent, `from_ts`/`to_ts`, `q` przez FTS), `limit` + `offset`; wyniki z `raw_json` odtwarzane do dict z `_category`.
   - **GET /api/stats**, **/api/telemetry**, **/api/network/analytics** – mogą być liczone po DB (GROUP BY, przedziały czasowe) zamiast po liście w pamięci; dla „ostatnie 24h” wystarczy `WHERE ts >= ?`.
   - **SSE /api/stream** – bez zmian: nowe wpisy z pętli poll nadal wysyłane z bufora w pamięci (minimalne opóźnienie).
3. **Start aplikacji**
   - Ładowanie początkowego bufora: ostatnie N wierszy z DB (lub z pliku, jak dziś) do pamięci; tail pliku nadal uzupełnia nowe wpisy i zapisuje je do DB.

---

## Konfiguracja

- **Baza jest domyślnie włączona** (`ENABLE_DB=1`). Wyłączenie: `ENABLE_DB=0`.

```bash
# Ścieżka do pliku SQLite (domyślnie: projekt/data/logs.db)
DB_PATH=/var/lib/networkc/logs.db

# Retencja: wpisy starsze niż N dni są usuwane (dla wszystkich agentów/hostów)
DB_RETENTION_DAYS=7

# Maksymalna liczba wpisów w pamięci (bufor „na żywo” i SSE)
MAX_LOGS_IN_MEMORY=5000
```

---

## Podsumowanie

- **Lepiej**: indeksy, filtry i FTS po dużej liczbie wpisów bez obciążania pamięci.
- **Szybciej**: zapytania z `WHERE` + `ORDER BY ts DESC LIMIT N` zamiast skanowania całej listy.
- **Retencja**: 7 dni (konfig. `DB_RETENTION_DAYS`) – dane starsze niż N dni są usuwane globalnie.

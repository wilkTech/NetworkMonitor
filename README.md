# networkC – NDR Viewer dla Wazuh

**Network Detection and Response (NDR)** – przeglądarka i analityka logów sieciowych oraz zdarzeń bezpieczeństwa w czasie rzeczywistym, oparta o **Wazuh Managera** i **Wazuh Agentów**.

---

## Opis projektu

**networkC** to aplikacja w stylu **NDR (Network Detection and Response)** do monitorowania, kategoryzacji i analizy zdarzeń z infrastruktury Wazuh. Czyta strumień alertów z pliku archiwum managera (`archives.json`), wzbogaca wpisy o kategorie i metadane sieciowe (SRC/DST, porty, protokoły, DNS), udostępnia interfejs webowy z live tail, dashboardem sieciowym, telemetrią i eksportem.

### Główne cechy (NDR)

- **Wykrywanie w sieci** – agregacja zdarzeń z wielu agentów (hostów), analiza ruchu (TCP/UDP/DNS, IP, porty), wykrywanie anomalii w czasie.
- **Odpowiedź na zdarzenia** – filtrowanie po severity, kategorii, agencie; alerty critical/high; eksport (JSON/CSV) do dalszej obróbki lub integracji.
- **Widoczność** – jeden dashboard dla wszystkich logów i osobny widok „Logi sieciowe” z metadanymi przepływu, top źródła/cele/porty/DNS, wykresy czasowe.
- **Źródło danych** – **Wazuh Manager** (archives) + dane z **Wazuh Agentów** (logi systemowe, eBPF network flow, DNS, firewall, rootcheck, SCA itd.).

Projekt nie zastępuje Wazuh, tylko rozszerza go o wygodny podgląd i analitykę sieciową w jednym miejscu.

---

## Architektura

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Hosty (serwery, stacje)                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                    │
│  │ Wazuh Agent  │  │ Wazuh Agent  │  │ Wazuh Agent  │  ...               │
│  │ (zbieranie   │  │ (zbieranie   │  │ (zbieranie   │                    │
│  │  logów,      │  │  logów,      │  │  logów,      │                    │
│  │  eBPF, DNS) │  │  eBPF, DNS)  │  │  eBPF, DNS)  │                    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                    │
└─────────┼────────────────┼─────────────────┼─────────────────────────────┘
          │                │                 │
          ▼                ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Wazuh Manager                                                           │
│  • Odbiera zdarzenia od agentów                                          │
│  • Zapisuje do /var/ossec/logs/archives/archives.json                    │
└─────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  networkC (ta aplikacja)                                                 │
│  • Tail archives.json w czasie rzeczywistym                              │
│  • Parsowanie JSON, kategoryzacja (decoder, rule, location, full_log)   │
│  • Metadane sieciowe: network_flow (eBPF), dns_query, kernel (SRC/DST)   │
│  • Bufor w pamięci + opcjonalnie SQLite (retencja, FTS, paginacja)       │
│  • FastAPI: /api/logs, /api/network/*, /api/telemetry, SSE, /metrics     │
└─────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Przeglądarka – dashboard: Wszystkie logi | Logi sieciowe | Telemetria  │
└─────────────────────────────────────────────────────────────────────────┘
```

Szczegóły **programu na agencie** (Wazuh Agent i moduły zbierające dane) opisane są w **[docs/AGENT_I_ZBIERANIE_DANYCH.md](docs/AGENT_I_ZBIERANIE_DANYCH.md)**.

---

## Wymagania

- **Python 3.10+**
- Dostęp do pliku archiwum Wazuh: `/var/ossec/logs/archives/archives.json` (zwykle na serwerze z Wazuh Managerem; można przekazać inną ścieżkę przez `OSSEC_ARCHIVES_PATH`).

## Zasób Wazuh

Projekt zależy od **Wazuh** (Manager zapisuje `archives.json`; opcjonalnie Agenci na hostach). Zasoby i opcjonalne dołączenie repozytorium Wazuh do tego repo (submoduł Git) opisane są w **[docs/WAZUH_ZASOBY.md](docs/WAZUH_ZASOBY.md)**.

- **Oficjalne repo:** [github.com/wazuh/wazuh](https://github.com/wazuh/wazuh)
- **Dokumentacja:** [documentation.wazuh.com](https://documentation.wazuh.com/)
- **Opcjonalnie w tym repo:** `git submodule add https://github.com/wazuh/wazuh.git wazuh` – szczegóły w dokumencie powyżej.

---

## Instalacja

```bash
git clone https://github.com/YOUR_ORG/networkC.git
cd networkC
pip install -r requirements.txt
```

Opcjonalnie: wirtualne środowisko:

```bash
python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

---

## Uruchomienie

```bash
python3 main.py
```

Aplikacja startuje na **http://0.0.0.0:8000** (domyślnie). Otwórz w przeglądarce adres serwera (np. `http://localhost:8000`).

### Zmienne środowiskowe

| Zmienna | Domyślna | Opis |
|---------|----------|------|
| `OSSEC_ARCHIVES_PATH` | `/var/ossec/logs/archives/archives.json` | Ścieżka do pliku archiwum Wazuh |
| `WEB_PORT` | `8000` | Port serwera HTTP |
| `WEB_HOST` | `0.0.0.0` | Host (0.0.0.0 = wszystkie interfejsy) |
| `MAX_LOGS_IN_MEMORY` | `5000` | Maks. liczba logów w pamięci |
| `TAIL_POLL_INTERVAL` | `0.5` | Interwał odświeżania odczytu (s) |
| `LOG_FILE` | `logs/app.log` | Ścieżka do logów aplikacji |
| `LOG_LEVEL` | `INFO` | Poziom logowania (DEBUG, INFO, WARNING, ERROR) |
| `CORS_ORIGINS` | *(puste)* | CORS: lista originów po przecinku; `*` = wszystkie |
| `SEARCH_MAX_RESULTS` | `2000` | Maks. wyników wyszukiwania pełnotekstowego |
| `TELEMETRY_HOURS` | `24` | Zakres czasowy telemetrii (godziny) |
| `ENABLE_REFRESH_ENDPOINT` | `true` | Endpoint `POST /api/refresh` (przeładowanie bufora) |
| `ALERTS_WINDOW_MINUTES` | `60` | Okno alertów critical/high (minuty) |
| `ENABLE_DB` | `1` | Baza SQLite (1 = włączona) |
| `DB_PATH` | `data/logs.db` | Ścieżka do pliku SQLite |
| `DB_RETENTION_DAYS` | `7` | Retencja: usuwanie wpisów starszych niż N dni |
| `CONFIG_FILE` | *(puste)* | Opcjonalny plik konfiguracyjny (JSON lub YAML) |
| `APP_VERSION` | `0.2.0` | Wersja (Serwis, `/api/health`) |
| `ARCHIVES_WAIT_SECONDS` | `10` | Czekanie na plik archiwum – interwał (s) |
| `ARCHIVES_WAIT_MAX_RETRIES` | `0` | Max prób (0 = bez limitu) |
| `DB_BATCH_SIZE` | `50` | Zapis do DB co N wpisów (0 = pojedynczo) |
| `DB_FLUSH_INTERVAL_SECONDS` | `5` | Okresowy flush bufora do DB (s) |

---

## Funkcje

- **Live tail** – śledzenie archiwum w stylu `tail -f`, nowe wpisy na bieżąco (SSE).
- **Kategoryzacja** – na podstawie `location`, `decoder.name`, `rule.level`/`rule.groups`, wzorców w `full_log` oraz `data.type` (np. `network_flow`, `dns_query`).
- **Filtry** – kategoria, severity, agent, wyszukiwanie pełnotekstowe, zakres czasu.
- **Dashboard sieciowy (NDR)** – analityka: SRC/DST, porty, protokoły, DNS, bajty; top źródła/cele/porty/agenci; wykresy; eksport CSV.
- **Telemetria** – serie czasowe (logi ogółem i sieciowe), rozkłady kategorii i severity.
- **Alerty** – liczba wpisów critical/high w ostatnich N minutach (`GET /api/alerts`).
- **Baza SQLite** – szybsze filtry, FTS5, paginacja, retencja; opcjonalnie wyłączenie (`ENABLE_DB=0`).
- **Metryki Prometheus** – `GET /metrics` (Grafana, Zabbix).
- **Zakładka Serwis** – wersja, stan pliku archiwum, ostatni odczyt, link do metryk.

---

## Struktura projektu

```
networkC/
├── config.py              # Konfiguracja (env + opcjonalnie plik)
├── main.py                # Punkt wejścia, uvicorn
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── docs/
│   ├── AGENT_I_ZBIERANIE_DANYCH.md   # Program na agencie – zbieranie danych
│   ├── ARCHITEKTURA_DANYCH.md
│   ├── BAZA_DANYCH.md
│   ├── REKOMENDACJE_ULEPSZEN.md
│   ├── ROZWÓJ_FUNKCJONALNY.md
│   ├── WAZUH_ZASOBY.md               # Zasób Wazuh – linki, opcjonalny submoduł
│   └── WERYFIKACJA_ODBIORU_I_PARSOWANIA.md
├── src/
│   ├── categorizer.py     # Kategoryzacja logów
│   ├── log_processor.py   # Tail + parsowanie JSON
│   ├── network_analytics.py  # Metadane sieciowe, agregacje
│   ├── telemetry.py       # Serie czasowe, rozkłady
│   ├── db.py              # SQLite, retencja, FTS
│   ├── metrics.py         # Prometheus
│   └── web_app.py         # FastAPI, SSE, UI
├── tests/
│   └── test_parsing.py    # Testy parsowania i kategoryzacji
├── data/                  # (tworzony) SQLite
└── logs/                  # (tworzony) logi aplikacji
```

---

## Rozszerzanie kategorii

W `src/categorizer.py`:

- **LOCATION_CATEGORIES** – mapowanie `location` → kategoria.
- **DECODER_CATEGORIES** – mapowanie `decoder.name` → kategoria.
- **JSON_DECODER_TYPES** – mapowanie `data.type` (np. `network_flow`, `dns_query`) → kategoria.
- **LOG_PATTERNS** – wzorce w `full_log` do wykrywania typu (np. ` SRC=`, `PROTO=TCP`, `iptables`).

---

## Testy

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Licencja

MIT – zobacz [LICENSE](LICENSE).

---

## Powiązane

- [Wazuh](https://www.wazuh.com/) – platforma XDR/SIEM (Manager + Agent).
- [docs/WAZUH_ZASOBY.md](docs/WAZUH_ZASOBY.md) – zasób Wazuh w projekcie (linki, opcjonalny submoduł Git).
- [docs/AGENT_I_ZBIERANIE_DANYCH.md](docs/AGENT_I_ZBIERANIE_DANYCH.md) – dane z agentów (logi, eBPF, DNS).

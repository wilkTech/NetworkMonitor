# Rekomendowane ulepszenia programu networkC

Dokument uzupełnia [ROZWÓJ_FUNKCJONALNY.md](ROZWÓJ_FUNKCJONALNY.md) o konkretne sugestie uporządkowane według priorytetu i nakładu pracy.

---

## Szybkie wdrożenie (niski nakład)

| Ulepszenie | Opis | Status |
|------------|------|--------|
| **Metryki Prometheus** | Endpoint `GET /metrics` (liczniki: wpisy w pamięci/DB, błędy odczytu, alerty). | **Zaimplementowane** – `src/metrics.py`, `GET /metrics` |
| **Rozszerzony health** | W `GET /api/health`: wersja, plik archiwum (istnieje, rozmiar), ostatni odczyt, błędy odczytu. | **Zaimplementowane** – `web_app.py` |
| **Konfiguracja z pliku** | Ładowanie ustawień z `config.yaml` / `config.json` z nadpisywaniem przez zmienne środowiskowe. | **Zaimplementowane** – `config.py`, zmienna `CONFIG_FILE` |
| **Top reguły (rule_id)** | W `GET /api/stats` pole `top_rules`; w UI blok „Najczęstsze reguły” na stronie wszystkich logów. | **Zaimplementowane** – `db.get_stats()`, `web_app` stats, zakładka + blok w HTML |
| **Zakładka Serwis** | Stan zdrowia i metryki w jednym miejscu w UI (wersja, archiwum, ostatni odczyt, link do `/metrics`). | **Zaimplementowane** – zakładka „🔧 Serwis” |

---

## Średni nakład, duży wpływ

| Ulepszenie | Opis | Uwagi |
|------------|------|--------|
| **Autentykacja** | Basic Auth lub API key dla `/api/*` i strony głównej. Bez tego dashboard jest otwarty dla każdego w sieci. | FastAPI: `HTTPBearer` lub `HTTPBasic`; opcjonalnie wyłączenie auth przez `ENABLE_AUTH=0` |
| **Webhook przy alertach** | Przy przekroczeniu progu critical/high – POST na konfigurowalny URL (Slack, Teams, Mattermost). | Nowy moduł `src/alerting.py`; konfig: `WEBHOOK_URL`, `WEBHOOK_THRESHOLD`; wywołanie z pętli poll lub po agregacji z `/api/alerts` |
| **Rate limiting** | Ograniczenie requestów na IP (np. 60/min dla `/api/export`, 30/min dla `/api/stream`). | slowapi lub własny middleware z użyciem cache (dict/Redis); konfig: `RATE_LIMIT_EXPORT`, `RATE_LIMIT_STREAM` |
| **Zakres czasu telemetrii** | Parametr `hours` lub `from_ts`/`to_ts` w `GET /api/telemetry` zamiast stałych 24h. | **Zaimplementowane** – API: `hours`, `from_ts`, `to_ts`; UI: select 6h–7d + przycisk „Pobierz” |
| **Paginacja w UI** | Frontend korzysta z `offset` w `GET /api/logs` – przycisk „Poprzednia” / „Następna”. | **Zaimplementowane** – „Wszystkie logi”: stronicowanie 200 wpisów; panel sieciowy: 500 wpisów + zakres czasu 1h–7d |

---

## Większy nakład, strategiczne

| Ulepszenie | Opis | Uwagi |
|------------|------|--------|
| **TLS/HTTPS** | Opcja uruchomienia uvicorn z certyfikatami (np. `--ssl-keyfile`, `--ssl-certfile`) lub reverse proxy (nginx) przed aplikacją. | Dla produkcji zalecany reverse proxy; w dokerze/kompose – jedna zmienna `TLS_CERT_PATH` i start z SSL |
| **Raporty okresowe** | Generowanie raportów PDF/HTML za dzień lub tydzień (podsumowanie kategorii, severity, top agenci, top reguły). | Biblioteka do PDF (weasyprint/reportlab) lub szablon HTML; job okresowy (cron) lub endpoint `POST /api/report?from=&to=` |
| **Konfiguracja reguł własnych** | Ładowanie wzorców (regex/contains) z pliku YAML bez zmian w kodzie – nowe kategorie lub dopasowania. | Rozszerzenie `categorizer.py`: ładowanie z pliku + merge z domyślnymi regułami |
| **Wieloźródłowość logów** | Obsługa wielu plików `archives.json` (np. z wielu managerów Wazuh) lub katalogu z rotowanymi plikami. | `LogProcessor` przyjmuje listę ścieżek lub katalog; równoległy tail/merge strumieni |

---

## Ulepszenia techniczne (jakość kodu i niezawodność)

| Ulepszenie | Opis | Status |
|------------|------|--------|
| **Graceful shutdown** | Przy SIGTERM: zatrzymanie pętli poll, zamknięcie połączenia do DB (`db.close()`), poprawne zakończenie strumieni SSE. | **Zaimplementowane** – `@app.on_event("shutdown")`: anulowanie zadania poll, flush bufora DB, `db.close()` |
| **Retry przy braku pliku** | Gdy `archives.json` nie istnieje (np. Wazuh jeszcze nie wystartował) – logowanie ostrzeżenia i ponawianie co N sekund zamiast twardego błędu startu. | **Zaimplementowane** – `wait_for_archives_path()` w config; zmienne `ARCHIVES_WAIT_SECONDS`, `ARCHIVES_WAIT_MAX_RETRIES` |
| **Batch insert do DB** | Zamiast `db.insert()` przy każdym wpisie – bufor 50–100 wpisów i jedna transakcja. Mniejszy narzut przy dużym ruchu. | **Zaimplementowane** – `db.insert_many()`, bufor w web_app z `DB_BATCH_SIZE` (domyślnie 50); flush przy shutdown |
| **Testy integracyjne** | Prosty test: uruchomienie `create_app()`, `GET /api/health`, `GET /api/stats` – weryfikacja, że aplikacja startuje i API odpowiada. |

---

## Proponowana kolejność

1. **Metryki Prometheus** + **rozszerzony health** – mały nakład, od razu użyteczne w produkcji.
2. **Top reguły** – dane już w DB, brak nowych źródeł.
3. **Autentykacja** (Basic Auth lub API key) – krytyczne, jeśli dashboard jest w sieci.
4. **Webhook przy alertach** – szybka reakcja zespołu bez zaglądania do UI.
5. **Paginacja w UI** – lepsze UX przy dużych wynikach (API gotowe).
6. **Konfiguracja z pliku** – wygoda wdrożenia.
7. **Rate limiting** – ochrona przed nadużyciami.

Reszta z listy według potrzeb (TLS, raporty, reguły własne, wieloźródłowość).

---

Jeśli wskażesz, które ulepszenie chcesz wdrożyć jako pierwsze, mogę zaproponować konkretne zmiany w kodzie (pliki, sygnatury, fragmenty).

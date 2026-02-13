# Architektura danych – podejście i opcje

## Obecny przepływ

```
Wazuh (archives.json) → LogProcessor (tail + parse) → [pamięć: deque 5000] + [bufor DB]
                                                              ↓                    ↓
                                                        SSE /api/stream      insert_many co 50 wpisów
                                                        /api/logs (fallback)      ↓
                                                                              SQLite (retencja 7 dni)
```

### Słabości

1. **Dwa źródła prawdy**  
   Lista „na żywo” jest w pamięci (`processor.entries`), zapytania z UI idą do bazy. Dopóki bufor nie zostanie zapisany (np. co 50 wpisów), w bazie brakuje najnowszych zdarzeń – użytkownik może nie widzieć ostatnich logów przy odświeżeniu lub po przełączeniu na „stronę z bazy”.

2. **Zależność od pliku**  
   Odczyt oparty jest o tail `archives.json`: rotacja, wieloliniowy JSON i ucięte wpisy wymagają resyncu (limit bufora, „stale” poll). Przy bardzo dużych lub „brudnych” wpisach strumień może się na chwilę zatrzymywać.

3. **Bufor DB tylko po rozmiarze**  
   Zapis do SQLite odbywa się przy `len(bufor) >= DB_BATCH_SIZE` (np. 50). Przy małym ruchu ostatnie zdarzenia długo siedzą tylko w pamięci – po restarcie lub przy odczycie z API z bazy ich nie ma.

---

## Proponowane kierunki

### 1. Jeden spójny obraz danych (bez zmiany bazy)

**Cel:** To, co widać w UI (lista + SSE), ma być spójne z tym, co jest w bazie, a najnowsze wpisy trafiają do bazy w rozsądnym czasie.

- **Okresowy flush bufora do DB (time-based)**  
  Oprócz flusha przy `DB_BATCH_SIZE` uruchomić zadanie w tle: co N sekund (np. 5) wywołać `_flush_db_buffer()`. Dzięki temu:
  - wpisy trafiają do SQLite nawet przy małym ruchu,
  - `/api/logs` zwraca aktualne dane z bazy,
  - po krótkim opóźnieniu (np. 5 s) źródłem prawdy staje się baza.

- **Opcjonalnie: „ostatnia minuta” z pamięci**  
  Dla `/api/logs` (i ewentualnie statystyk) można łączyć: ostatnie N sekund z `processor.entries` + reszta z bazy. Redukuje to efekt opóźnienia flusha, ale komplikuje API (deduplikacja, sortowanie). Na start wystarczy **time-based flush**.

- **SSE nadal z pamięci**  
  Strumień może dalej brać wpisy z `processor.entries` (najmniejsze opóźnienie). Ważne, żeby równolegle dane były zapisywane do bazy (stąd okresowy flush).

**Efekt:** Bez zmiany bazy (SQLite) i bez zmiany źródła (plik Wazuh) – bardziej przewidywalne i spójne zachowanie oraz szybsze pojawianie się danych w DB.

---

### 2. Źródło danych (czy tylko plik?)

| Opcja | Opis | Kiedy rozważyć |
|--------|------|------------------|
| **Plik archives.json (obecne)** | Tail + parsowanie JSON, resync przy rotacji/ucięciu | Standardowa instalacja Wazuh, brak API / Indexera |
| **Wazuh API** | Zapytania do API (np. alerty, zdarzenia) z filtrami | Gdy potrzebne są tylko alerty/reguły, bez pełnego archiwum |
| **Wazuh Indexer (Elastic)** | Integracja z indeksem Wazuh (zapytania, dashboardy) | Środowisko z pełnym stackiem Wazuh (Indexer + Dashboard) |

Obecnie Wazuh nie oferuje prostego „streamu zdarzeń” po HTTP – archiwum to pliki. Dlatego **tail pliku pozostaje sensownym wyborem**, a ulepszenia dotyczą głównie **zapisu do bazy i spójności** (time-based flush, ewentualnie jeden spójny odczyt z DB + mały bufor na SSE).

---

### 3. Wybór bazy danych

| Baza | Zalety | Wady | Kiedy |
|------|--------|------|--------|
| **SQLite** | Jeden plik, brak serwera, FTS5, WAL, retencja, indeksy | Jeden piszący proces, limit przy bardzo dużym ruchu | **Domyślnie** – pojedyncza instancja, do setek tysięcy wpisów, retencja 7–30 dni |
| **PostgreSQL** | Współbieżny zapis/odczyt, lepsze skalowanie, zaawansowane zapytania | Wymaga serwera, konfiguracja | Wiele instancji aplikacji, współdzielona baza, wyższe wolumeny |
| **ClickHouse** | Logi/time-series, kompresja, TTL, bardzo szybkie agregacje | Osobny serwis, inna składnia SQL | Bardzo duże wolumeny (miliony wpisów/dzień), długie retencje, analityka |

**Rekomendacja na teraz:** Zostać przy **SQLite** i poprawić architekturę danych (time-based flush, ewentualnie docelowo „jeden źródło prawdy = DB”). Zmiana na PostgreSQL lub ClickHouse ma sens przy konkretnej potrzebie (skalowanie, wiele węzłów, bardzo duże wolumeny).

---

### 4. Dalsze kroki (opcjonalne)

- **Abstrakcja warstwy zapisu**  
  Interfejs typu `LogStore` (insert, query, get_recent) z implementacjami: SQLite, (w przyszłości) PostgreSQL. Ułatwi ewentualną zmianę bazy bez ruszania logiki aplikacji.

- **Integracja z Wazuh API**  
  Jeśli w przyszłości pojawi się endpoint „stream alertów” lub będzie potrzebny tylko podzbiór zdarzeń – osobny adapter mógłby uzupełniać lub zastąpić odczyt z pliku.

- **Wazuh Indexer**  
  Dla środowisk już opartych o Elastic stack – rozważyć zapytania do Indexera zamiast (lub obok) lokalnej bazy, z zachowaniem obecnego UI jako „lightweight viewer”.

---

## Podsumowanie

- **Od razu:** Wprowadzić **okresowy flush bufora do DB** (np. co 5 s) – konfigurowalny interwał. To poprawia spójność i „świeżość” danych w SQLite bez zmiany bazy ani źródła.
- **Źródło:** Na razie **archives.json** (tail) – adekwatne do typowej instalacji Wazuh.
- **Baza:** **SQLite** pozostaje domyślna; PostgreSQL/ClickHouse – gdy pojawią się wymagania skalowania lub bardzo dużych wolumenów.

Szczegóły schematu SQLite, retencji i FTS – patrz [BAZA_DANYCH.md](BAZA_DANYCH.md).

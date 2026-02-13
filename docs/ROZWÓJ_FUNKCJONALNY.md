# Propozycja rozwoju funkcjonalnego – OSSEC/Wazuh Log Viewer

Dokument opisuje kierunki rozwoju projektu **networkC** (OSSEC/Wazuh Log Viewer) z podziałem na obszary i priorytety.

---

## 1. Bezpieczeństwo i operacje

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Autentykacja** | Logowanie (np. Basic Auth, API key lub integracja z OAuth/LDAP) dla `/api/*` i strony głównej | Wysoki |
| **Role i uprawnienia** | Różne poziomy dostępu: tylko odczyt, eksport, odświeżanie bufora, konfiguracja | Średni |
| **Audit log** | Rejestrowanie kto i kiedy korzystał z eksportu, odświeżania, wyszukiwania (opcjonalnie) | Niski |
| **Rate limiting** | Ograniczenie liczby requestów na IP/klucz, szczególnie dla `/api/export` i `/api/stream` | Średni |
| **TLS/HTTPS** | Opcja uruchomienia serwera z TLS (certyfikaty) dla produkcji | Wysoki |

---

## 2. Doświadczenie użytkownika (UX/UI)

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Zapisane filtry / widoki** | Zapis nazwanych zestawów filtrów (kategoria + severity + agent + czas) i szybkie przełączanie | Średni |
| **Historia wyszukiwań** | Ostatnie zapytania pełnotekstowe (`q`) w dropdown lub lista pod polem wyszukiwania | Niski |
| **Paginacja po stronie serwera** | `offset`/`cursor` w `GET /api/logs` zamiast obciążania frontu dużymi listami | Średni |
| **Ciemny/jasny motyw** | Przełącznik theme w UI (obecnie tylko ciemny) | Niski |
| **Responsywność** | Lepsze dostosowanie tabel i wykresów do małych ekranów (mobile/tablet) | Średni |
| **Powiadomienia dźwiękowe** | Opcjonalny dźwięk przy nowych alertach critical/high (SSE) | Niski |
| **Eksport z zaznaczenia** | Eksport tylko zaznaczonych wierszy w tabeli logów (checkbox) | Średni |

---

## 3. Analityka i raportowanie

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Własny zakres czasu telemetrii** | Parametr `hours` lub `from_ts`/`to_ts` w `/api/telemetry` zamiast stałych 24h | Średni |
| **Raporty okresowe** | Generowanie raportów (np. PDF/HTML) za dzień/tydzień – podsumowanie kategorii, severity, top agenci, top reguły | Wysoki |
| **Wykresy porównawcze** | Porównanie dwóch przedziałów czasowych (np. ten tydzień vs poprzedni) | Niski |
| **Top reguły (rule_id)** | Statystyki „najczęstsze reguły” w `/api/stats` i osobny blok w UI | Średni |
| **Korelacja alertów** | Proste wykrywanie serii (np. ten sam agent + ta sama reguła w krótkim czasie) | Niski |
| **GeoIP (opcjonalnie)** | Wzbogacanie adresów SRC/DST o kraj/miasto (np. MaxMind) w widoku sieciowym | Niski |

---

## 4. Integracje i automatyzacja

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Webhook przy alertach** | Przy przekroczeniu progu critical/high – wysłanie POST na konfigurowalny URL (Slack, Teams, custom) | Wysoki |
| **Integracja z systemem ticketowym** | Przycisk „Utwórz ticket” przy wpisie z przekazaniem kontekstu (reguła, agent, fragment logu) | Średni |
| **Webhook dla nowych logów** | Opcjonalne przekazywanie wybranych logów (np. po kategorii) na zewnętrzny endpoint | Niski |
| **API webhooków** | CRUD webhooków (URL, filtry, secret) przez API lub prosty plik konfiguracyjny | Średni |

---

## 5. Wydajność i skala

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Wieloźródłowość logów** | Obsługa wielu plików `archives.json` (np. z wielu managerów) lub katalogu z rotowanymi plikami | Średni |
| **Indeksowanie / cache** | Opcjonalny indeks (np. SQLite/Elasticsearch) dla szybszego wyszukiwania i filtrów czasowych przy dużych wolumenach | Wysoki (dla dużych instalacji) — **zrealizowane: SQLite + FTS5, patrz docs/BAZA_DANYCH.md** |
| **Kompresja odpowiedzi** | Włączenie gzip dla `GET /api/logs` i `/api/export` | Niski |
| **Ograniczenie SSE** | Opcja throttlingu lub „tylko critical/high” w strumieniu, żeby ograniczyć ruch | Średni |

---

## 6. Dane i źródła

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Wazuh API** | Pobieranie logów/alertów z Wazuh API zamiast/oprócz pliku (np. dla archiwum lub wielu managerów) | Średni |
| **Syslog / TCP** | Odbieranie logów przez syslog (UDP/TCP) lub gniazdo TCP jako alternatywne źródło | Niski |
| **Konfigurowalna ścieżka** | Wielość ścieżek w konfiguracji (np. lista plików lub katalogów) z wyborem w UI | Niski |

---

## 7. Konfiguracja i DevOps

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Konfiguracja z pliku** | Ładowanie ustawień z pliku (YAML/JSON) z nadpisywaniem przez zmienne środowiskowe | Średni |
| **Health check rozszerzony** | Endpoint `/api/health` zwracający: ostatni czas odczytu pliku, liczbę wpisów, status pliku archiwum | Średni |
| **Metryki Prometheus** | Endpoint `/metrics` (liczniki logów, alertów, błędy odczytu) do monitoringu stosu | Wysoki |
| **Graceful shutdown** | Korygowanie zamykania SSE i zapisywania stanu przy SIGTERM | Niski |

---

## 8. Kategoryzacja i reguły

| Funkcja | Opis | Priorytet |
|--------|------|-----------|
| **Reguły własne** | Ładowanie dodatkowych wzorców (regex/contains) z pliku konfiguracyjnego bez zmian w kodzie | Średni |
| **Tagowanie ręczne** | Możliwość dodania tagu/notatki do wpisu (w pamięci lub w zewnętrznym store) | Niski |
| **Whitelist reguł** | Ukrywanie lub obniżanie severity wybranych rule_id (np. fałszywe alarmy) | Średni |

---

## Podsumowanie priorytetów

- **Wysoki:** autentykacja, TLS, raporty okresowe, webhook przy alertach, indeksowanie przy dużych wolumenach, metryki Prometheus.
- **Średni:** role, rate limiting, zapisane filtry, paginacja, top reguły, webhook API, wieloźródłowość, konfig z pliku, rozszerzony health, reguły własne, whitelist.
- **Niski:** audit log, historia wyszukiwań, theme, powiadomienia dźwiękowe, wykresy porównawcze, korelacja, GeoIP, syslog, konfiguracja wielu ścieżek, graceful shutdown, tagowanie ręczne.

Dokument można traktować jako roadmap – do realizacji warto wybierać najpierw elementy z obszarów **Bezpieczeństwo**, **Integracje** i **Analityka**, a następnie **Wydajność** i **UX**.

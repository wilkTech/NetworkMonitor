# Program na agencie – wyciąganie i wysyłanie danych

W architekturze **networkC** dane trafiają do aplikacji z pliku archiwum **Wazuh Managera** (`archives.json`). Ten plik jest zapisywany przez Managera na podstawie zdarzeń przesyłanych przez **Wazuh Agentów** działających na hostach (serwerach, stacjach roboczych).

„Program na agencie”, który **wyciąga dane** z systemu i wysyła je do Managera, to w praktyce **Wazuh Agent** oraz wbudowane i opcjonalne moduły Wazuh (np. zbieranie logów, syscollector, integracje eBPF). Poniżej opisane są te składniki i rodzaje danych istotne dla **NDR** (logi sieciowe, przepływ, DNS).

---

## 1. Wazuh Agent – rola

**Wazuh Agent** to lekki proces działający na każdym monitorowanym hoście. Jego zadania m.in.:

- Zbieranie logów z plików, journald, syslog.
- Wykonywanie skanów (rootcheck, SCA – Security Configuration Assessment).
- Zbieranie inwentarza i zmian (syscollector) – opcjonalnie.
- Wysyłanie zdarzeń do **Wazuh Managera** (szyfrowany kanał).

Manager zapisuje zdarzenia m.in. do `archives.json`. **networkC** czyta ten plik (tail w czasie rzeczywistym), parsuje JSON i wyświetla/analizuje dane w dashboardzie. Sam **nie instaluje** nic na agentach – korzysta z tego, co już wysyła Wazuh Agent (i ewentualne integracje).

---

## 2. Co „wyciąga” agent – źródła danych

Dane widoczne w networkC pochodzą z:

### 2.1. Zbieranie logów (Log collection)

- **Lokalne pliki logów** – Agent czyta pliki wskazane w konfiguracji Managera (np. `/var/log/auth.log`, logi aplikacji).
- **Journald / systemd** – zdarzenia z `journald` (location np. `journald`).
- **Syslog** – zdarzenia z demona syslog.

Te logi często zawierają wpisy **kernel/iptables/nftables** (np. `SRC=`, `DST=`, `PROTO=TCP`, `DPT=`). **networkC** wyciąga z nich metadane sieciowe w `network_analytics.parse_network_meta()` i kategoryzuje je jako „Ruch sieciowy” / „Firewall”.

### 2.2. Moduły Wazuh na agencie

- **Rootcheck** – skan integralności i znanych zagrożeń (location: `rootcheck`).
- **SCA (Security Configuration Assessment)** – compliance (np. CIS); location: `sca`.
- **Syscollector** (opcjonalnie) – inwentarz: pakiety, porty, procesy, interfejsy sieciowe. Niektóre dane (np. porty nasłuchujące) mogą pojawić się w archiwum i są kategoryzowane w networkC (np. „Porty nasłuchujące”).

### 2.3. Dane sieciowe (NDR) – eBPF i integracje

Aby w networkC pojawiały się **przepływy sieciowe (network_flow)** i **zapytania DNS** w strukturalnym formacie (`data.type == "network_flow"` / `"dns_query"`), na agentach musi być włączone zbieranie tych danych. Wazuh umożliwia to m.in. przez:

- **Integrację eBPF / network** – moduł zbierający zdarzenia sieciowe (np. połączenia TCP/UDP, adresy, porty, bajty) i ewentualnie DNS, wysyłający je do Managera w formacie JSON. W archiwum pojawiają się wpisy z `data.type == "network_flow"` lub `"dns_query"`.
- **Konfiguracja po stronie Managera** – włączenie odpowiednich integracji/decoderów dla agentów.

Konfiguracja dokładnie zależy od wersji Wazuh (np. integracja eBPF w dokumentacji Wazuh). **networkC** nie wymusza konkretnej wersji; wystarczy, że w `archives.json` pojawiają się wpisy z:

- `data.type == "network_flow"` (src_ip, dst_ip, protocol, porty, bytes itd.),
- `data.type == "dns_query"` (query, qtype itd.),

albo że metadane sieciowe da się wyciągnąć z `full_log` (kernel), co aplikacja obsługuje w `parse_network_meta_from_entry()`.

### 2.4. Inne zdarzenia z agenta

- Start/stop Wazuh („Started Wazuh”, „Agent started”) – wykrywane po wzorcach w `full_log`.
- Sesje (session opened/closed), sudo, PAM – często z logów systemowych lub decoderów Wazuh (pam, sudo, sshd).
- Historia logowań (np. `last -n`) – kategoryzowana jako „Logowania (IP)” w networkC.

---

## 3. Przepływ od agenta do networkC (skrót)

1. **Host** – działa **Wazuh Agent** (oraz ewentualnie moduły eBPF/syscollector).
2. Agent **zbiera** logi, zdarzenia sieciowe (eBPF), DNS, skanuje pliki/konfigurację itd.
3. Agent **wysyła** zdarzenia do **Wazuh Managera**.
4. Manager **zapisuje** je do `archives.json` (i innych logów).
5. **networkC** **czyta** `archives.json` (tail), parsuje JSON, kategoryzuje wpisy i wyciąga metadane sieciowe.
6. Użytkownik przegląda **dashboard** (wszystkie logi, logi sieciowe, telemetria) w przeglądarce.

---

## 4. Podsumowanie – „program na agencie”

| Element | Opis |
|--------|------|
| **Program na agencie** | **Wazuh Agent** (+ opcjonalne moduły: syscollector, integracje eBPF/network). |
| **Co wyciąga** | Logi z plików/journald/syslog, zdarzenia kernela (SRC/DST/PROTO), rootcheck, SCA; opcjonalnie przepływ sieciowy (eBPF) i zapytania DNS w formacie `data.type` (network_flow, dns_query). |
| **Gdzie wysyła** | Do **Wazuh Managera**. |
| **Gdzie to widać w networkC** | W pliku `archives.json` na Managerze; networkC czyta ten plik i pokazuje dane w UI oraz w analityce sieciowej (NDR). |

Nie ma oddzielnego, własnego „programu na agencie” w repozytorium networkC – aplikacja zakłada, że infrastruktura Wazuh (Agenty + Manager) już zbiera i zapisuje zdarzenia; networkC pełni rolę **przeglądarki i warstwy NDR** nad tym strumieniem.

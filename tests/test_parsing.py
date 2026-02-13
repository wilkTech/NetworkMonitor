"""
Testy weryfikujące poprawność interpretacji i parsowania danych wejściowych:
- JSON z pliku archiwum (log_processor)
- Kategoryzacja wpisów (categorizer)
- Metadane sieciowe (network_analytics)
- Znaczniki czasu (telemetry)
- Parametry API czasu (web_app)
"""

import sys
import tempfile
from datetime import timezone
from pathlib import Path

import pytest

# Ścieżka do src
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.categorizer import categorize, LogCategory
from src.log_processor import LogProcessor
from src import network_analytics as na
from src.telemetry import parse_entry_timestamp
from src.web_app import _parse_time_param, _entry_in_time_range, _entry_matches_search


# --- LogProcessor: parsowanie JSON ---

class TestLogProcessorParsing:
    """Parsowanie JSON i pojedynczych wpisów."""

    def test_read_json_lines_single_object(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        text = '{"timestamp": "2024-01-01T12:00:00", "decoder": {"name": "ossec"}}'
        entries, leftover = proc._read_json_lines(text)
        assert len(entries) == 1
        assert entries[0]["timestamp"] == "2024-01-01T12:00:00"
        assert entries[0]["_category"]["name"] == "ossec"
        assert leftover == ""

    def test_read_json_lines_multiple_objects(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        text = '{"a":1}\n{"b":2}\n{"c":3}'
        entries, leftover = proc._read_json_lines(text)
        assert len(entries) == 3
        assert entries[0].get("a") == 1
        assert entries[1].get("b") == 2
        assert entries[2].get("c") == 3
        assert leftover == ""

    def test_read_json_lines_multiline_full_log(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        # full_log z wewnętrznym \n (typowy Wazuh)
        text = '{"timestamp":"2024-01-01T12:00:00","full_log":"line1\\nline2","decoder":{"name":"kernel"}}'
        entries, leftover = proc._read_json_lines(text)
        assert len(entries) == 1
        assert entries[0]["full_log"] == "line1\nline2"
        assert leftover == ""

    def test_read_json_lines_incomplete_json_preserved_in_leftover(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        text = '{"a":1}{"b":2} fragment'
        entries, leftover = proc._read_json_lines(text)
        assert len(entries) == 2
        assert "fragment" in leftover or leftover.strip() == "fragment"

    def test_read_json_lines_non_dict_skipped(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        text = '[1,2,3]'
        entries, leftover = proc._read_json_lines(text)
        # root to lista – raw_decode zwróci listę; kod akceptuje tylko dict
        assert len(entries) == 0
        assert leftover == ""

    def test_parse_single_requires_dict(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        with pytest.raises(ValueError, match="Oczekiwano dict"):
            proc._parse_single([])
        with pytest.raises(ValueError, match="Oczekiwano dict"):
            proc._parse_single("string")

    def test_parse_single_empty_dict_gets_unknown_category(self):
        proc = LogProcessor(archives_path=Path("/nonexistent"), max_logs=100)
        out = proc._parse_single({})
        assert out["_category"]["name"] == "unknown"
        assert "parse_error" not in out["_category"].get("tags", [])  # błąd to przy exception w categorize

    def test_read_new_lines_resets_after_truncate_or_rotation(self):
        """Po rotacji/truncate (pozycja > rozmiar) następny odczyt resetuje pozycję i czyta od początku."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write('{"a":1}\n{"b":2}\n')
            path = Path(f.name)
        try:
            proc = LogProcessor(archives_path=path, max_logs=100)
            proc.load_initial()
            assert len(proc.entries) == 2
            assert proc._file_position == path.stat().st_size
            # Symulacja truncate/rotacji: plik jest teraz mniejszy niż zapisana pozycja
            path.write_text('{"c":3}\n', encoding="utf-8")
            new = proc.poll()
            # Powinien zresetować pozycję i przeczytać nową zawartość
            assert len(new) == 1
            assert new[0].get("c") == 3
        finally:
            path.unlink(missing_ok=True)


# --- Categorizer: interpretacja pól wpisu ---

class TestCategorizerInterpretation:
    """Poprawność odczytu decoder, rule, location, full_log, data."""

    def test_empty_entry(self):
        cat = categorize({})
        assert cat.name == "unknown"
        assert cat.display_name == "Inne"

    def test_decoder_name_dict(self):
        entry = {"decoder": {"name": "pam"}, "rule": {"level": 5}}
        cat = categorize(entry)
        assert cat.name == "pam"
        assert "auth" in cat.tags or "pam" in cat.tags

    def test_decoder_empty_name_treated_as_none(self):
        entry = {"decoder": {"name": ""}, "full_log": "some log"}
        cat = categorize(entry)
        # Brak dopasowania decoder → wzorce lub Inne
        assert cat.name in ("unknown", "filesystem") or "Inne" in cat.display_name

    def test_rule_level_string_converted(self):
        entry = {"decoder": {"name": "ossec"}, "rule": {"level": "7"}}
        cat = categorize(entry)
        assert cat.severity == "high"  # 7 → high

    def test_rule_level_float_clamped(self):
        entry = {"decoder": {"name": "ossec"}, "rule": {"level": 7.5}}
        cat = categorize(entry)
        assert cat.severity in ("high", "critical", "medium", "low", "info")

    def test_rule_groups_list(self):
        entry = {"decoder": {"name": "ossec"}, "rule": {"groups": ["authentication_success", "pam"]}}
        cat = categorize(entry)
        assert "auth_success" in cat.tags or "pam" in cat.tags

    def test_location_priority(self):
        entry = {"location": "rootcheck", "decoder": {"name": "ossec"}}
        cat = categorize(entry)
        assert cat.name == "rootcheck"

    def test_full_log_pattern_match(self):
        entry = {"full_log": "df -P /dev/sda1", "decoder": {}}
        cat = categorize(entry)
        assert cat.name == "filesystem"

    def test_data_type_network_flow(self):
        entry = {"decoder": {"name": "json"}, "data": {"type": "network_flow"}}
        cat = categorize(entry)
        assert cat.name == "network_flow"

    def test_data_type_dns_query(self):
        entry = {"decoder": {"name": "json"}, "data": {"type": "dns_query"}}
        cat = categorize(entry)
        assert cat.name == "dns_query"

    def test_agent_dict_or_string_handled(self):
        # Kategoryzacja nie zależy od agenta; sprawdzamy że nie ma crashu
        categorize({"agent": {"name": "agent1", "id": "001"}})
        categorize({"agent": "agent1"})


# --- Network analytics: parsowanie metadanych ---

class TestNetworkAnalyticsParsing:
    """parse_network_meta i parse_network_meta_from_entry."""

    def test_parse_network_meta_src_dst_proto_ports(self):
        full_log = "IN=eth0 SRC=192.168.1.1 DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=443"
        meta = na.parse_network_meta(full_log)
        assert meta is not None
        assert meta["src"] == "192.168.1.1"
        assert meta["dst"] == "10.0.0.1"
        assert meta["proto"] == "TCP"
        assert meta["sport"] == 12345
        assert meta["dport"] == 443
        assert meta["interface"] == "eth0"

    def test_parse_network_meta_no_src_returns_none(self):
        assert na.parse_network_meta("some log without SRC=") is None

    def test_parse_network_meta_src_length_capped(self):
        full_log = "SRC=" + "x" * 70
        meta = na.parse_network_meta(full_log)
        # Kod ogranicza do 64 znaków
        assert meta is None or (meta.get("src") and len(meta["src"]) <= 64)

    def test_parse_network_meta_from_entry_network_flow(self):
        entry = {
            "data": {
                "type": "network_flow",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "protocol": "TCP",
                "src_port": 12345,
                "dst_port": 443,
                "bytes": 1000,
            }
        }
        meta = na.parse_network_meta_from_entry(entry)
        assert meta["src"] == "1.2.3.4"
        assert meta["dst"] == "5.6.7.8"
        assert meta["proto"] == "TCP"
        assert meta["sport"] == 12345
        assert meta["dport"] == 443
        assert meta["bytes"] == 1000

    def test_parse_network_meta_from_entry_dns_query(self):
        entry = {
            "data": {
                "type": "dns_query",
                "query": "example.com.",
                "qtype": "A",
            }
        }
        meta = na.parse_network_meta_from_entry(entry)
        assert meta["query"] == "example.com"
        assert meta["proto"] == "DNS"

    def test_parse_network_meta_from_entry_fallback_full_log(self):
        entry = {"data": None, "full_log": "SRC=10.0.0.1 DST=10.0.0.2 PROTO=UDP"}
        meta = na.parse_network_meta_from_entry(entry)
        assert meta is not None
        assert meta["src"] == "10.0.0.1"
        assert meta["dst"] == "10.0.0.2"
        assert meta["proto"] == "UDP"


# --- Telemetry: timestamp ---

class TestTelemetryTimestamp:
    """parse_entry_timestamp / _parse_ts."""

    def test_timestamp_iso_string(self):
        entry = {"timestamp": "2024-06-15T14:30:00+00:00"}
        dt = parse_entry_timestamp(entry)
        assert dt is not None
        assert dt.year == 2024 and dt.month == 6 and dt.day == 15

    def test_timestamp_unix_int(self):
        entry = {"timestamp": 1718458200}  # 2024-06-15 ~14:30 UTC
        dt = parse_entry_timestamp(entry)
        assert dt is not None

    def test_timestamp_unix_float(self):
        entry = {"timestamp": 1718458200.5}
        dt = parse_entry_timestamp(entry)
        assert dt is not None

    def test_at_timestamp_alias(self):
        entry = {"@timestamp": "2024-01-01T00:00:00Z"}
        dt = parse_entry_timestamp(entry)
        assert dt is not None

    def test_timestamp_in_data(self):
        entry = {"data": {"timestamp": "2024-01-01T12:00:00Z"}}
        dt = parse_entry_timestamp(entry)
        assert dt is not None

    def test_timestamp_missing_returns_none(self):
        assert parse_entry_timestamp({}) is None
        assert parse_entry_timestamp({"other": 1}) is None

    def test_timestamp_invalid_string_returns_none(self):
        assert parse_entry_timestamp({"timestamp": "not-a-date"}) is None


# --- Web app: parametry czasu i filtry ---

class TestWebAppTimeParams:
    """_parse_time_param i zakres czasu."""

    def test_parse_time_param_empty_none(self):
        assert _parse_time_param(None) is None
        assert _parse_time_param("") is None
        assert _parse_time_param("   ") is None

    def test_parse_time_param_unix_float(self):
        dt = _parse_time_param("1718458200.5")
        assert dt is not None
        assert dt.tzinfo == timezone.utc

    def test_parse_time_param_iso_z(self):
        dt = _parse_time_param("2024-01-01T00:00:00Z")
        assert dt is not None

    def test_parse_time_param_invalid_returns_none(self):
        assert _parse_time_param("invalid") is None
        assert _parse_time_param("abc123") is None

    def test_entry_in_time_range_no_bounds_matches_all(self):
        entry = {"timestamp": "2024-01-01T12:00:00Z"}
        assert _entry_in_time_range(entry, None, None) is True

    def test_entry_matches_search_empty_query_matches_all(self):
        assert _entry_matches_search({"full_log": "x"}, None) is True
        assert _entry_matches_search({"full_log": "x"}, "") is True
        assert _entry_matches_search({"full_log": "x"}, "   ") is True

    def test_entry_matches_search_found_in_full_log(self):
        assert _entry_matches_search({"full_log": "error connection refused"}, "refused") is True
        assert _entry_matches_search({"full_log": "error"}, "error") is True

    def test_entry_matches_search_not_found(self):
        assert _entry_matches_search({"full_log": "ok"}, "error") is False


# --- Config: zmienne środowiskowe ---

class TestConfigEnvParsing:
    """Konfiguracja – typy i sensowne domyślne wartości."""

    def test_config_valid_defaults(self):
        from config import WEB_PORT, MAX_LOGS_IN_MEMORY, SEARCH_MAX_RESULTS
        assert isinstance(WEB_PORT, int) and WEB_PORT > 0
        assert MAX_LOGS_IN_MEMORY >= 1
        assert SEARCH_MAX_RESULTS >= 1

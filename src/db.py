"""
Warstwa bazy danych SQLite dla logów Wazuh.

Zapewnia indeksowane zapytania (czas, kategoria, severity, agent, FTS),
retencję czasową (np. 7 dni dla wszystkich agentów/hostów) oraz zapis/odczyt
wpisów z zachowaniem pełnego JSON.
"""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

from .telemetry import parse_entry_timestamp

logger = logging.getLogger(__name__)


def _extract_agent_name(entry: dict) -> str:
    a = entry.get("agent")
    if isinstance(a, dict):
        return str(a.get("name") or a.get("id") or "")
    return str(a) if a is not None else ""


def _extract_rule_fields(entry: dict) -> tuple[str, str]:
    r = entry.get("rule") or {}
    rid = str(r.get("id") or "")
    desc = str(r.get("description") or "")[:500]
    return rid, desc


def _extract_network_fields(entry: dict) -> dict[str, Any]:
    """Pobiera pola sieciowe z _network_meta lub data/full_log (do indeksów)."""
    meta = entry.get("_network_meta")
    if isinstance(meta, dict):
        return {
            "src": (meta.get("src") or "")[:64] if meta.get("src") else None,
            "dst": (meta.get("dst") or "")[:64] if meta.get("dst") else None,
            "proto": (meta.get("proto") or "")[:16] if meta.get("proto") else None,
            "dport": meta.get("dport") if isinstance(meta.get("dport"), (int, type(None))) else None,
            "query": (meta.get("query") or "")[:512] if meta.get("query") else None,
        }
    return {}


def _entry_to_ts(entry: dict) -> Optional[float]:
    dt = parse_entry_timestamp(entry)
    if dt is None:
        return None
    return dt.timestamp()


class LogDatabase:
    """SQLite: tabela log_entries + FTS5 do pełnotekstowego wyszukiwania."""

    def __init__(self, db_path: Path, retention_days: int = 7):
        self.db_path = Path(db_path)
        self.retention_days = max(1, retention_days)
        self._conn: Optional[sqlite3.Connection] = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._create_schema()
        return self._conn

    def _create_schema(self) -> None:
        conn = self._conn
        conn.execute("""
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL,
                ts_iso TEXT,
                category_name TEXT,
                category_key TEXT,
                severity TEXT,
                agent_name TEXT,
                rule_id TEXT,
                rule_description TEXT,
                full_log TEXT,
                raw_json TEXT,
                network_src TEXT,
                network_dst TEXT,
                network_proto TEXT,
                network_dport INTEGER,
                network_query TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_ts ON log_entries(ts DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_category ON log_entries(category_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_severity ON log_entries(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_agent ON log_entries(agent_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_network_src ON log_entries(network_src)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_network_dst ON log_entries(network_dst)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_log_network_proto ON log_entries(network_proto)")

        # FTS5 dla full_log i rule_description
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS log_entries_fts USING fts5(
                full_log,
                rule_description,
                content='log_entries',
                content_rowid='id'
            )
        """)
        # Trigger: synchronizacja FTS z główną tabelą (SQLite FTS5 external content)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS log_entries_fts_insert AFTER INSERT ON log_entries BEGIN
                INSERT INTO log_entries_fts(rowid, full_log, rule_description)
                VALUES (new.id, new.full_log, new.rule_description);
            END
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS log_entries_fts_delete AFTER DELETE ON log_entries BEGIN
                INSERT INTO log_entries_fts(log_entries_fts, rowid, full_log, rule_description)
                VALUES ('delete', old.id, old.full_log, old.rule_description);
            END
        """)
        conn.commit()

    def _row_from_entry(self, entry: dict) -> tuple:
        """Przygotowuje krotkę wiersza do INSERT z wpisu (już skategoryzowanego)."""
        ts = _entry_to_ts(entry)
        ts_iso = entry.get("timestamp") or entry.get("@timestamp") or ""
        if isinstance(ts_iso, (int, float)):
            ts_iso = str(ts_iso)
        cat = entry.get("_category") or {}
        category_name = (cat.get("display_name") or "Inne")[:200]
        category_key = (cat.get("name") or "")[:100]
        severity = (cat.get("severity") or "info")[:50]
        agent_name = _extract_agent_name(entry)[:200]
        rule_id, rule_description = _extract_rule_fields(entry)
        full_log = (entry.get("full_log") or "")[:1_000_000]
        raw_json = json.dumps(entry, default=str, ensure_ascii=False)
        net = _extract_network_fields(entry)
        return (
            ts, ts_iso, category_name, category_key, severity, agent_name,
            rule_id, rule_description, full_log, raw_json,
            net.get("src"), net.get("dst"), net.get("proto"), net.get("dport"), net.get("query"),
        )

    def insert(self, entry: dict) -> None:
        """Wstawia jeden wpis (już skategoryzowany, z _category)."""
        conn = self._get_conn()
        conn.execute(
            """
            INSERT INTO log_entries (
                ts, ts_iso, category_name, category_key, severity, agent_name,
                rule_id, rule_description, full_log, raw_json,
                network_src, network_dst, network_proto, network_dport, network_query
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            self._row_from_entry(entry),
        )
        conn.commit()
        self._trim_by_retention(conn)

    def insert_many(self, entries: list[dict]) -> None:
        """Wstawia wiele wpisów w jednej transakcji (mniejszy narzut przy dużym ruchu)."""
        if not entries:
            return
        conn = self._get_conn()
        row_tuples = [self._row_from_entry(e) for e in entries]
        conn.executemany(
            """
            INSERT INTO log_entries (
                ts, ts_iso, category_name, category_key, severity, agent_name,
                rule_id, rule_description, full_log, raw_json,
                network_src, network_dst, network_proto, network_dport, network_query
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            row_tuples,
        )
        conn.commit()
        self._trim_by_retention(conn)

    def _trim_by_retention(self, conn: sqlite3.Connection) -> None:
        """Usuwa wpisy starsze niż retention_days (dla wszystkich agentów/hostów)."""
        cutoff_ts = time.time() - (self.retention_days * 86400)
        cur = conn.execute("DELETE FROM log_entries WHERE ts IS NOT NULL AND ts < ?", (cutoff_ts,))
        deleted = cur.rowcount
        if deleted > 0:
            conn.commit()
            logger.info("Retencja bazy logów: usunięto %d wpisów starszych niż %d dni", deleted, self.retention_days)
            if deleted >= 1000:
                try:
                    conn.execute("VACUUM")
                    conn.commit()
                except sqlite3.OperationalError:
                    pass

    def query(
        self,
        *,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent: Optional[str] = None,
        network_only: bool = False,
        q: Optional[str] = None,
        from_ts: Optional[float] = None,
        to_ts: Optional[float] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """
        Zwraca (listę wpisów jako dict z _category, total).
        Wpisy w kolejności od najnowszych (DESC).
        """
        conn = self._get_conn()
        params: list[Any] = []
        where_parts: list[str] = ["1=1"]

        if from_ts is not None:
            where_parts.append("ts >= ?")
            params.append(from_ts)
        if to_ts is not None:
            where_parts.append("ts <= ?")
            params.append(to_ts)
        if category:
            where_parts.append("category_name = ?")
            params.append(category)
        if severity:
            where_parts.append("severity = ?")
            params.append(severity)
        if agent:
            where_parts.append("(agent_name = ? OR agent_name LIKE ?)")
            params.append(agent, f"%{agent}%")
        if network_only:
            where_parts.append(
                "(network_src IS NOT NULL OR network_dst IS NOT NULL OR network_proto IS NOT NULL OR network_query IS NOT NULL)"
            )

        placeholders = " AND ".join(where_parts)
        if q and q.strip():
            fts_param = _fts_query_escape(q.strip())
            if fts_param:
                from_sql = "log_entries e INNER JOIN log_entries_fts f ON e.id = f.rowid AND f.log_entries_fts MATCH ?"
                params_count = [fts_param] + params
                params_limit = params_count + [limit, offset]
                count_sql = f"SELECT COUNT(*) FROM {from_sql} WHERE {placeholders}"
                list_sql = f"""
                    SELECT e.raw_json FROM {from_sql}
                    WHERE {placeholders}
                    ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?
                """
                cur = conn.execute(count_sql, params_count)
                total = cur.fetchone()[0]
                cur = conn.execute(list_sql, params_limit)
            else:
                cur = conn.execute(
                    f"SELECT COUNT(*) FROM log_entries WHERE {placeholders}",
                    params,
                )
                total = cur.fetchone()[0]
                cur = conn.execute(
                    f"""
                    SELECT raw_json FROM log_entries
                    WHERE {placeholders}
                    ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?
                    """,
                    params + [limit, offset],
                )
        else:
            cur = conn.execute(
                f"SELECT COUNT(*) FROM log_entries WHERE {placeholders}",
                params,
            )
            total = cur.fetchone()[0]
            cur = conn.execute(
                f"""
                SELECT raw_json FROM log_entries
                WHERE {placeholders}
                ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            )

        rows = cur.fetchall()
        entries = []
        for row in rows:
            try:
                entries.append(json.loads(row[0]))
            except (json.JSONDecodeError, TypeError):
                continue
        return entries, total

    def get_recent(self, n: int) -> list[dict]:
        """Ostatnie n wpisów (do uzupełnienia bufora przy starcie)."""
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT raw_json FROM log_entries ORDER BY ts DESC, id DESC LIMIT ?",
            (n,),
        )
        entries = []
        for row in cur.fetchall():
            try:
                entries.append(json.loads(row[0]))
            except (json.JSONDecodeError, TypeError):
                continue
        return list(reversed(entries))  # najstarszy first, jak w deque

    def get_entries_in_time_range(
        self, from_ts: float, to_ts: float, limit: int = 50_000
    ) -> list[dict]:
        """Wpisy w zakresie czasowym (do telemetrii/analityki)."""
        conn = self._get_conn()
        cur = conn.execute(
            """
            SELECT raw_json FROM log_entries
            WHERE ts >= ? AND ts <= ?
            ORDER BY ts ASC
            LIMIT ?
            """,
            (from_ts, to_ts, limit),
        )
        entries = []
        for row in cur.fetchall():
            try:
                entries.append(json.loads(row[0]))
            except (json.JSONDecodeError, TypeError):
                continue
        return entries

    def get_stats(self) -> dict[str, Any]:
        """Agregacje: total, by_category, by_severity, agents, network_count."""
        conn = self._get_conn()
        cur = conn.execute("SELECT COUNT(*) FROM log_entries")
        total = cur.fetchone()[0]

        cur = conn.execute(
            "SELECT category_name, COUNT(*) FROM log_entries GROUP BY category_name"
        )
        by_category = {row[0]: row[1] for row in cur.fetchall()}

        cur = conn.execute(
            "SELECT severity, COUNT(*) FROM log_entries GROUP BY severity"
        )
        by_severity = {row[0]: row[1] for row in cur.fetchall()}

        cur = conn.execute(
            "SELECT DISTINCT agent_name FROM log_entries WHERE agent_name != '' ORDER BY agent_name"
        )
        agents = [row[0] for row in cur.fetchall()]

        cur = conn.execute(
            """
            SELECT COUNT(*) FROM log_entries
            WHERE network_src IS NOT NULL OR network_dst IS NOT NULL
               OR network_proto IS NOT NULL OR network_query IS NOT NULL
            """
        )
        network_count = cur.fetchone()[0]

        cur = conn.execute(
            """
            SELECT rule_id, rule_description, COUNT(*) AS cnt
            FROM log_entries
            WHERE rule_id IS NOT NULL AND rule_id != ''
            GROUP BY rule_id
            ORDER BY cnt DESC
            LIMIT 20
            """
        )
        top_rules = [{"rule_id": row[0], "description": (row[1] or "")[:120], "count": row[2]} for row in cur.fetchall()]

        return {
            "total": total,
            "by_category": by_category,
            "by_severity": by_severity,
            "agents": agents,
            "network_count": network_count,
            "top_rules": top_rules,
        }

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None


def _fts_query_escape(q: str) -> str:
    """Escape dla FTS5: podwójne cudzysłowy i ewentualnie OR/AND w cudzysłowach."""
    q = q.replace('"', '""').strip()
    if not q:
        return ""
    # Proste zapytanie: wszystkie słowa jako phrase lub term
    terms = q.split()
    return " ".join(f'"{t}"' for t in terms if t)

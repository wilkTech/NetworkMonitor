"""
Aplikacja webowa - dashboard logów Wazuh z aktualizacjami na żywo.
"""

import asyncio
import csv
import io
import json
import logging
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from sse_starlette.sse import EventSourceResponse

from config import (
    ALERTS_WINDOW_MINUTES,
    APP_VERSION,
    CORS_ORIGINS,
    DB_BATCH_SIZE,
    DB_FLUSH_INTERVAL_SECONDS,
    DB_PATH,
    DB_RETENTION_DAYS,
    ENABLE_DB,
    ENABLE_REFRESH_ENDPOINT,
    SEARCH_MAX_RESULTS,
)
from .db import LogDatabase
from .log_processor import LogProcessor
from . import metrics as metrics_module
from . import network_analytics as na
from . import telemetry as tel
from .telemetry import parse_entry_timestamp

logger = logging.getLogger(__name__)

# Globalny procesor - inicjalizowany w main
processor: Optional[LogProcessor] = None

# Baza danych (opcjonalnie)
_db: Optional[LogDatabase] = None
_db_buffer: list = []
_db_buffer_lock = threading.Lock()
_poll_task: Optional[asyncio.Task] = None
_flush_task: Optional[asyncio.Task] = None


def _get_db() -> Optional[LogDatabase]:
    return _db


def _flush_db_buffer() -> None:
    """Zapisuje bufor wpisów do bazy (wywoływane przy batch flush i przy shutdown)."""
    global _db_buffer
    db = _get_db()
    if not db:
        return
    with _db_buffer_lock:
        to_flush = _db_buffer[:]
        _db_buffer.clear()
    if to_flush:
        try:
            db.insert_many(to_flush)
        except Exception as ex:
            logger.exception("Batch zapis do bazy: %s", ex)


def _entry_matches_search(entry: dict, query: str) -> bool:
    """Sprawdza, czy wpis zawiera frazę (full_log, rule, decoder, data)."""
    if not query or not query.strip():
        return True
    q = query.strip().lower()
    full_log = (entry.get("full_log") or "").lower()
    if q in full_log:
        return True
    rule = entry.get("rule") or {}
    if q in (rule.get("description") or "").lower():
        return True
    decoder = entry.get("decoder") or {}
    if q in (decoder.get("name") or "").lower():
        return True
    for key in ("location", "id", "level"):
        val = rule.get(key)
        if val is not None and q in str(val).lower():
            return True
    data = entry.get("data")
    if isinstance(data, dict):
        for v in data.values():
            if v is not None and q in str(v).lower():
                return True
    return False


def _parse_time_param(ts: Optional[str], default_offset_hours: Optional[float] = None) -> Optional[datetime]:
    """Parsuje opcjonalny parametr czasu (ISO lub unix)."""
    if not ts or not ts.strip():
        if default_offset_hours is not None:
            return datetime.now(timezone.utc) - timedelta(hours=default_offset_hours)
        return None
    ts = ts.strip()
    try:
        if ts.replace(".", "", 1).replace("-", "", 1).isdigit():
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _entry_in_time_range(
    entry: dict,
    from_dt: Optional[datetime],
    to_dt: Optional[datetime],
) -> bool:
    """Sprawdza, czy wpis mieści się w zakresie czasowym."""
    if from_dt is None and to_dt is None:
        return True
    ts = parse_entry_timestamp(entry)
    if ts is None:
        return True
    try:
        ts_utc = ts.astimezone(timezone.utc) if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    except Exception:
        return True
    if from_dt and ts_utc < from_dt:
        return False
    if to_dt and ts_utc > to_dt:
        return False
    return True


def create_app(archives_path: Path, max_logs: int = 5000, poll_interval: float = 0.5) -> FastAPI:
    global processor, _db, _poll_task, _flush_task

    app = FastAPI(
        title="OSSEC/Wazuh Log Viewer",
        description="Monitorowanie logów Wazuh w czasie rzeczywistym",
    )

    if CORS_ORIGINS:
        origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]
        if "*" in origins:
            origins = ["*"]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=origins != ["*"],
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["*"],
        )
    
    if ENABLE_DB:
        _db = LogDatabase(Path(DB_PATH), retention_days=DB_RETENTION_DAYS)
        batch_size = max(0, DB_BATCH_SIZE)
    
        def _on_new_entry(entry: dict) -> None:
            if batch_size <= 0:
                try:
                    _db.insert(entry)
                except Exception as ex:
                    logger.exception("Zapis do bazy: %s", ex)
                return
            with _db_buffer_lock:
                _db_buffer.append(entry)
                if len(_db_buffer) >= batch_size:
                    to_flush = _db_buffer[:]
                    _db_buffer.clear()
                else:
                    to_flush = []
            if to_flush:
                try:
                    _db.insert_many(to_flush)
                except Exception as ex:
                    logger.exception("Batch zapis do bazy: %s", ex)
        _on_new = _on_new_entry
    else:
        _on_new = None
    
    def _on_read_error() -> None:
        metrics_module.increment_read_errors()
    
    processor = LogProcessor(
        archives_path=archives_path,
        max_logs=max_logs,
        poll_interval=poll_interval,
        on_new_entry=_on_new,
        on_read_error=_on_read_error,
    )
    
    @app.on_event("startup")
    async def startup():
        global _poll_task, _flush_task
        processor.load_initial()
        metrics_module.set_last_read_time()
        logger.info("Aplikacja uruchomiona, załadowano %d wpisów", len(processor.entries))
        async def poll_loop():
            while True:
                try:
                    await asyncio.to_thread(processor.poll)
                    metrics_module.set_last_read_time()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.exception("Błąd poll: %s", e)
                await asyncio.sleep(0.5)
        _poll_task = asyncio.create_task(poll_loop())
    
        if ENABLE_DB and DB_FLUSH_INTERVAL_SECONDS > 0:
            async def flush_loop():
                while True:
                    try:
                        await asyncio.sleep(DB_FLUSH_INTERVAL_SECONDS)
                        _flush_db_buffer()
                    except asyncio.CancelledError:
                        break
                    except Exception as e:
                        logger.exception("Błąd okresowego flushu DB: %s", e)
            _flush_task = asyncio.create_task(flush_loop())
            logger.info("Włączono okresowy zapis bufora do DB co %s s", DB_FLUSH_INTERVAL_SECONDS)
    
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return get_index_html()
    
    @app.get("/api/health")
    async def health():
        """Stan zdrowia: status, wersja, plik archiwum, ostatni odczyt, metryki."""
        archive_path = processor.archives_path
        try:
            archive_exists = archive_path.exists()
            archive_size_bytes = archive_path.stat().st_size if archive_exists else None
        except OSError:
            archive_exists = False
            archive_size_bytes = None
        last_ts = metrics_module.get_last_read_timestamp()
        last_read_iso = datetime.utcfromtimestamp(last_ts).isoformat() + "Z" if last_ts else None
        out = {
            "status": "ok",
            "version": APP_VERSION,
            "logs_loaded": len(processor.entries),
            "archive_path": str(archive_path),
            "archive_exists": archive_exists,
            "archive_size_bytes": archive_size_bytes,
            "last_read_iso": last_read_iso,
            "read_errors_total": metrics_module.get_read_errors_total(),
        }
        db = _get_db()
        if db:
            try:
                st = db.get_stats()
                out["db_total"] = st.get("total", 0)
            except Exception:
                out["db_total"] = None
        else:
            out["db_total"] = None
        return out
    
    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics():
        """Metryki w formacie Prometheus (dla Grafana/Zabbix)."""
        to_dt = datetime.now(timezone.utc)
        from_dt = to_dt - timedelta(minutes=ALERTS_WINDOW_MINUTES)
        from_ts_f = from_dt.timestamp()
        to_ts_f = to_dt.timestamp()
        alerts_critical, alerts_high = 0, 0
        db = _get_db()
        if db:
            entries, _ = db.query(from_ts=from_ts_f, to_ts=to_ts_f, limit=50_000)
            for e in entries:
                sev = (e.get("_category") or {}).get("severity")
                if sev == "critical":
                    alerts_critical += 1
                elif sev == "high":
                    alerts_high += 1
            try:
                st = db.get_stats()
                entries_in_db = st.get("total", 0)
            except Exception:
                entries_in_db = None
        else:
            entries = [e for e in processor.entries if _entry_in_time_range(e, from_dt, to_dt)]
            for e in entries:
                sev = (e.get("_category") or {}).get("severity")
                if sev == "critical":
                    alerts_critical += 1
                elif sev == "high":
                    alerts_high += 1
            entries_in_db = None
        body = metrics_module.render_prometheus(
            entries_in_memory=len(processor.entries),
            entries_in_db=entries_in_db,
            alerts_critical=alerts_critical,
            alerts_high=alerts_high,
        )
        return PlainTextResponse(body, media_type="text/plain; charset=utf-8")
    
    @app.get("/api/config")
    async def get_config():
        """Konfiguracja dostępna dla frontendu (np. czy włączyć przycisk odświeżania)."""
        return {"refresh_enabled": ENABLE_REFRESH_ENDPOINT}
    
    @app.get("/api/logs")
    async def get_logs(
        limit: int = 200,
        offset: int = 0,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent: Optional[str] = None,
        network_only: bool = False,
        q: Optional[str] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
        last_hours: Optional[float] = None,
    ):
        """Pobiera ostatnie logi z opcjonalnymi filtrami (kategoria, severity, agent, wyszukiwanie, zakres czasu)."""
        limit = min(max(1, limit), SEARCH_MAX_RESULTS)
        offset = max(0, offset)
        from_dt = _parse_time_param(from_ts)
        to_dt = _parse_time_param(to_ts)
        if last_hours is not None and last_hours > 0:
            if to_dt is None:
                to_dt = datetime.now(timezone.utc)
            from_dt = to_dt - timedelta(hours=last_hours)
        from_ts_f = from_dt.timestamp() if from_dt else None
        to_ts_f = to_dt.timestamp() if to_dt else None
    
        db = _get_db()
        if db:
            entries, total = db.query(
                category=category,
                severity=severity,
                agent=agent,
                network_only=network_only,
                q=q,
                from_ts=from_ts_f,
                to_ts=to_ts_f,
                limit=limit,
                offset=offset,
            )
            if network_only:
                enriched = []
                for e in entries:
                    try:
                        enriched.append(na.enrich_network_entry(e))
                    except Exception:
                        enriched.append(e)
                entries = enriched
            return {"logs": entries, "total": total}
        # Tryb tylko pamięć
        entries = list(reversed(processor.entries))
        if network_only:
            entries = [e for e in entries if na.is_network_log(e)]
        if category:
            entries = [e for e in entries if e.get("_category", {}).get("display_name") == category]
        if severity:
            entries = [e for e in entries if e.get("_category", {}).get("severity") == severity]
        if agent:
            def _agent_matches(e: dict) -> bool:
                a = e.get("agent")
                if isinstance(a, dict):
                    return agent in str(a.get("name", "")) or agent in str(a.get("id", ""))
                if isinstance(a, str):
                    return agent in a
                return False
            entries = [e for e in entries if _agent_matches(e)]
        if q:
            entries = [e for e in entries if _entry_matches_search(e, q)]
        if from_dt is not None or to_dt is not None:
            entries = [e for e in entries if _entry_in_time_range(e, from_dt, to_dt)]
        total = len(entries)
        entries = entries[offset : offset + limit]
        if network_only:
            enriched = []
            for e in entries:
                try:
                    enriched.append(na.enrich_network_entry(e))
                except Exception:
                    enriched.append(e)
                entries = enriched
        return {"logs": entries, "total": total}
    
    @app.get("/api/network/analytics")
    async def get_network_analytics(
        hours: Optional[float] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
    ):
        """Pełna analityka logów sieciowych: typy, protokoły, agenty, top IP/porty. Zakres: hours lub from_ts/to_ts (domyślnie 24h)."""
        to_dt = _parse_time_param(to_ts)
        from_dt = _parse_time_param(from_ts)
        if to_dt is None:
            to_dt = datetime.now(timezone.utc)
        if from_dt is None:
            h = 24.0 if hours is None else max(0.25, min(168, float(hours)))
            from_dt = to_dt - timedelta(hours=h)
        from_ts_f = from_dt.timestamp()
        to_ts_f = to_dt.timestamp()
        db = _get_db()
        if db:
            entries = db.get_entries_in_time_range(from_ts_f, to_ts_f)
        else:
            entries = [e for e in processor.entries if _entry_in_time_range(e, from_dt, to_dt)]
        network_entries = [e for e in entries if na.is_network_log(e)]
        return na.compute_network_analytics(network_entries)
    
    @app.get("/api/telemetry")
    async def get_telemetry(
        bucket_minutes: int = 5,
        hours: Optional[float] = None,
        from_ts: Optional[str] = None,
        to_ts: Optional[str] = None,
    ):
        """Telemetria: serie czasowe, rozkłady. Zakres: hours (domyślnie 24) lub from_ts/to_ts."""
        to_dt = _parse_time_param(to_ts)
        from_dt = _parse_time_param(from_ts)
        if to_dt is None:
            to_dt = datetime.now(timezone.utc)
        if from_dt is None:
            h = 24.0 if hours is None else max(0.25, min(168, float(hours)))
            from_dt = to_dt - timedelta(hours=h)
        from_ts_f = from_dt.timestamp()
        to_ts_f = to_dt.timestamp()
        db = _get_db()
        if db:
            entries = db.get_entries_in_time_range(from_ts_f, to_ts_f)
        else:
            entries = [e for e in processor.entries if _entry_in_time_range(e, from_dt, to_dt)]
        bucket = min(60, max(1, bucket_minutes))
        return tel.compute_telemetry(
            entries,
            bucket_minutes=bucket,
            start=from_dt,
            end=to_dt,
        )
    
    @app.get("/api/stats")
    async def get_stats():
        """Statystyki kategoryzacji + top reguły (rule_id)."""
        db = _get_db()
        if db:
            return db.get_stats()
        entries = list(processor.entries)
        by_category = {}
        by_severity = {}
        by_rule: dict[str, tuple[str, int]] = {}  # rule_id -> (description, count)
        agents = set()
        network_count = 0
        for e in entries:
            if na.is_network_log(e):
                network_count += 1
            cat = e.get("_category") or {}
            cname = cat.get("display_name", "Inne")
            by_category[cname] = by_category.get(cname, 0) + 1
            sev = cat.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            r = e.get("rule") or {}
            rid = str(r.get("id") or "").strip()
            if rid:
                desc = (str(r.get("description") or ""))[:120]
                if rid not in by_rule:
                    by_rule[rid] = (desc, 0)
                by_rule[rid] = (by_rule[rid][0], by_rule[rid][1] + 1)
            a = e.get("agent")
            if isinstance(a, dict):
                aname = a.get("name") or a.get("id")
                if aname:
                    agents.add(str(aname))
            elif isinstance(a, str) and a.strip():
                agents.add(a.strip())
        top_rules = [
            {"rule_id": k, "description": v[0], "count": v[1]}
            for k, v in sorted(by_rule.items(), key=lambda x: -x[1][1])[:20]
        ]
        return {
            "total": len(entries),
            "network_count": network_count,
            "by_category": by_category,
            "by_severity": by_severity,
            "agents": list(agents),
            "top_rules": top_rules,
        }
    
    @app.get("/api/alerts")
    async def get_alerts(minutes: int = 0):
        """Liczba wpisów critical/high w ostatnich N minutach (do monitoringu)."""
        window = minutes if minutes > 0 else ALERTS_WINDOW_MINUTES
        to_dt = datetime.now(timezone.utc)
        from_dt = to_dt - timedelta(minutes=window)
        from_ts_f = from_dt.timestamp()
        to_ts_f = to_dt.timestamp()
        db = _get_db()
        if db:
            entries, _ = db.query(
                from_ts=from_ts_f, to_ts=to_ts_f, limit=50_000,
            )
            entries = [e for e in entries if (e.get("_category") or {}).get("severity") in ("critical", "high")]
        else:
            entries = [
                e
                for e in processor.entries
                if _entry_in_time_range(e, from_dt, to_dt)
                and (e.get("_category") or {}).get("severity") in ("critical", "high")
            ]
        by_sev = {"critical": 0, "high": 0}
        for e in entries:
            sev = (e.get("_category") or {}).get("severity")
            if sev in by_sev:
                by_sev[sev] += 1
        return {
            "window_minutes": window,
            "critical": by_sev["critical"],
            "high": by_sev["high"],
            "total": len(entries),
        }
    
    if ENABLE_REFRESH_ENDPOINT:
    
        @app.post("/api/refresh")
        async def refresh_logs():
            """Przeładowuje bufor logów z pliku (ostatnie N wpisów)."""
            try:
                n = processor.load_initial()
                return {"status": "ok", "loaded": n}
            except Exception as e:
                logger.exception("Błąd odświeżania: %s", e)
                raise HTTPException(status_code=500, detail=str(e))
    
    @app.get("/api/export")
    async def export_logs(
        format: str = "json",
        limit: int = 5000,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        agent: Optional[str] = None,
        network_only: bool = False,
        q: Optional[str] = None,
        last_hours: Optional[float] = None,
    ):
        """Eksport logów w formacie JSON lub CSV (te same filtry co /api/logs)."""
        limit = min(max(1, limit), SEARCH_MAX_RESULTS)
        to_dt = datetime.now(timezone.utc)
        from_dt = to_dt - timedelta(hours=last_hours) if (last_hours and last_hours > 0) else None
        from_ts_f = from_dt.timestamp() if from_dt else None
        to_ts_f = to_dt.timestamp()
    
        db = _get_db()
        if db:
            entries, _ = db.query(
                category=category,
                severity=severity,
                agent=agent,
                network_only=network_only,
                q=q,
                from_ts=from_ts_f,
                to_ts=to_ts_f,
                limit=limit,
                offset=0,
            )
        else:
            entries = list(reversed(processor.entries))
            if network_only:
                entries = [e for e in entries if na.is_network_log(e)]
            if category:
                entries = [e for e in entries if e.get("_category", {}).get("display_name") == category]
            if severity:
                entries = [e for e in entries if e.get("_category", {}).get("severity") == severity]
            if agent:
                def _agent_matches(e: dict) -> bool:
                    a = e.get("agent")
                    if isinstance(a, dict):
                        return agent in str(a.get("name", "")) or agent in str(a.get("id", ""))
                    if isinstance(a, str):
                        return agent in a
                    return False
                entries = [e for e in entries if _agent_matches(e)]
            if q:
                entries = [e for e in entries if _entry_matches_search(e, q)]
            if from_dt is not None:
                entries = [e for e in entries if _entry_in_time_range(e, from_dt, to_dt)]
            entries = entries[:limit]
        if format == "csv":
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(
                ["timestamp", "category", "severity", "agent", "rule_id", "rule_description", "full_log"]
            )
            for e in entries:
                c = e.get("_category") or {}
                a = e.get("agent")
                aname = a.get("name") or a.get("id") if isinstance(a, dict) else a
                r = e.get("rule") or {}
                writer.writerow([
                    e.get("timestamp", ""),
                    c.get("display_name", ""),
                    c.get("severity", ""),
                    aname or "",
                    r.get("id", ""),
                    r.get("description", ""),
                    (e.get("full_log") or "").replace("\n", " "),
                ])
            return Response(
                content=("\ufeff" + out.getvalue()).encode("utf-8"),
                media_type="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": "attachment; filename=wazuh-logs-export.csv"
                },
            )
        return Response(
            content=json.dumps({"logs": entries}, default=str, ensure_ascii=False),
            media_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=wazuh-logs-export.json"
            },
        )
    
    @app.get("/api/stream")
    async def stream_logs(request: Request):
        """SSE - strumień nowych logów na żywo. Tylko główna pętla (startup) wywołuje poll();
        stream tylko odczytuje nowe wpisy z processor.entries (brak wyścigów przy dostępie do pliku)."""
    
        async def event_generator():
            last_count = len(processor.entries)
            while True:
                if await request.is_disconnected():
                    break
                current = processor.entries
                if len(current) > last_count:
                    new_entries = list(current)[-(len(current) - last_count):]
                    last_count = len(current)
                    for e in new_entries:
                        try:
                            if na.is_network_log(e):
                                e = na.enrich_network_entry(e)
                        except Exception:
                            pass
                        yield {
                            "event": "log",
                            "data": json.dumps(e, default=str, ensure_ascii=False),
                        }
                await asyncio.sleep(0.5)
    
        return EventSourceResponse(event_generator())
    
    @app.on_event("shutdown")
    async def shutdown():
        """Graceful shutdown: zatrzymanie polla, zatrzymanie flushu, zapis bufora DB, zamknięcie połączenia."""
        global _poll_task, _flush_task
        if _flush_task and not _flush_task.done():
            _flush_task.cancel()
            try:
                await _flush_task
            except asyncio.CancelledError:
                pass
        if _poll_task and not _poll_task.done():
            _poll_task.cancel()
            try:
                await _poll_task
            except asyncio.CancelledError:
                pass
        _flush_db_buffer()
        db = _get_db()
        if db:
            try:
                db.close()
            except Exception as ex:
                logger.exception("Zamknięcie bazy: %s", ex)
        logger.info("Aplikacja zakończona (graceful shutdown)")
    
    return app


def get_index_html() -> str:
    return """<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OSSEC / Wazuh Log Viewer</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0f0f12;
      --bg-card: #16161a;
      --bg-hover: #1c1c22;
      --border: #2a2a32;
      --text: #e4e4e7;
      --text-muted: #71717a;
      --accent: #06b6d4;
      --accent-dim: #0891b2;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
      --info: #3b82f6;
      --radius: 8px;
      --shadow: 0 4px 24px rgba(0,0,0,0.4);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Space Grotesk', sans-serif;
      background: var(--bg-dark);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
    }
    .header {
      background: linear-gradient(135deg, var(--bg-card) 0%, #1a1a24 100%);
      border-bottom: 1px solid var(--border);
      padding: 1.25rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .header h1 {
      font-size: 1.5rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .header h1::before {
      content: "🛡️";
    }
    .live-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      background: rgba(34, 197, 94, 0.15);
      color: var(--success);
      padding: 0.35rem 0.7rem;
      border-radius: 999px;
      font-size: 0.8rem;
      font-weight: 500;
    }
    .live-badge::before {
      content: "";
      width: 6px;
      height: 6px;
      background: currentColor;
      border-radius: 50%;
      animation: pulse 1.5s infinite;
    }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
    .stats {
      display: flex;
      gap: 1.5rem;
      flex-wrap: wrap;
    }
    .stat {
      background: var(--bg-hover);
      padding: 0.5rem 1rem;
      border-radius: var(--radius);
      font-size: 0.9rem;
    }
    .stat strong { color: var(--accent); }
    .filters {
      padding: 1rem 2rem;
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      align-items: center;
      border-bottom: 1px solid var(--border);
    }
    .filters select, .filters input {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.5rem 0.75rem;
      border-radius: var(--radius);
      font-family: inherit;
      font-size: 0.9rem;
    }
    .filters select:focus, .filters input:focus {
      outline: none;
      border-color: var(--accent);
    }
    .logs-container {
      padding: 1rem 2rem 2rem;
      max-height: calc(100vh - 180px);
      overflow-y: auto;
    }
    .log-entry {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem 1.25rem;
      margin-bottom: 0.75rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.85rem;
      transition: background 0.2s, border-color 0.2s;
    }
    .log-entry:hover {
      background: var(--bg-hover);
      border-color: var(--accent-dim);
    }
    .log-entry .meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .log-entry .meta span {
      display: inline-flex;
      align-items: center;
      gap: 0.25rem;
    }
    .log-entry .category-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-weight: 500;
      font-size: 0.75rem;
    }
    .log-entry .severity-low { background: rgba(34,197,94,0.2); color: #4ade80; }
    .log-entry .severity-info { background: rgba(59,130,246,0.2); color: #60a5fa; }
    .log-entry .severity-medium { background: rgba(234,179,8,0.2); color: #facc15; }
    .log-entry .severity-high { background: rgba(249,115,22,0.2); color: #fb923c; }
    .log-entry .severity-critical { background: rgba(239,68,68,0.2); color: #f87171; }
    .log-entry .full-log {
      word-break: break-word;
      white-space: pre-wrap;
      max-height: 4.5em;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .log-entry.expanded .full-log {
      max-height: none;
    }
    .log-entry .expand-btn {
      margin-top: 0.5rem;
      background: none;
      border: none;
      color: var(--accent);
      cursor: pointer;
      font-size: 0.75rem;
      padding: 0;
    }
    .log-entry .expand-btn:hover { text-decoration: underline; }
    .empty-state {
      text-align: center;
      padding: 3rem 2rem;
      color: var(--text-muted);
    }
    .tabs {
      display: flex;
      gap: 0;
      padding: 0 2rem;
      border-bottom: 1px solid var(--border);
      background: var(--bg-card);
    }
    .tab {
      padding: 1rem 1.5rem;
      cursor: pointer;
      font-weight: 500;
      color: var(--text-muted);
      border-bottom: 2px solid transparent;
      transition: color 0.2s, border-color 0.2s;
    }
    .tab:hover { color: var(--text); }
    .tab.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }
    .section { display: none; padding: 1rem 2rem 2rem; }
    .section.active { display: block; }
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }
    .section-header h2 {
      font-size: 1.1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .network-section .log-entry {
      border-left: 3px solid #0ea5e9;
    }
    .net-analytics {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .net-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1rem;
      text-align: center;
    }
    .net-card .value { font-size: 1.5rem; font-weight: 700; color: var(--accent); }
    .net-card .label { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }
    .net-tables {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .net-table-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .net-table-card h3 {
      font-size: 0.9rem;
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border);
      margin: 0;
    }
    .net-table-card table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
    .net-table-card th, .net-table-card td { padding: 0.4rem 1rem; text-align: left; }
    .net-table-card th { color: var(--text-muted); font-weight: 500; }
    .net-table-card tr:nth-child(even) { background: var(--bg-hover); }
    .net-filters {
      display: flex;
      gap: 0.75rem;
      flex-wrap: wrap;
      margin-bottom: 1rem;
      align-items: center;
    }
    .net-filters select {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.4rem 0.75rem;
      border-radius: var(--radius);
      font-size: 0.9rem;
    }
    .net-log-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem;
      font-size: 0.75rem;
      margin-top: 0.35rem;
    }
    .net-log-meta span {
      background: var(--bg-hover);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
    }
    .net-panel-table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--bg-card);
      margin-bottom: 1rem;
    }
    .net-panel-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      font-family: 'JetBrains Mono', monospace;
    }
    .net-panel-table th {
      background: var(--bg-hover);
      color: var(--text-muted);
      font-weight: 600;
      padding: 0.65rem 0.75rem;
      text-align: left;
      white-space: nowrap;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      user-select: none;
    }
    .net-panel-table th:hover { color: var(--accent); }
    .net-panel-table th .sort-icon { margin-left: 0.25rem; opacity: 0.6; }
    .net-panel-table th.sorted-asc .sort-icon::after { content: ' ▲'; }
    .net-panel-table th.sorted-desc .sort-icon::after { content: ' ▼'; }
    .net-panel-table td {
      padding: 0.5rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .net-panel-table tr:hover td { background: var(--bg-hover); }
    .net-panel-table .col-time { min-width: 165px; }
    .net-panel-table .col-cat { min-width: 120px; }
    .net-panel-table .col-src { min-width: 110px; }
    .net-panel-table .col-dst { min-width: 110px; }
    .net-panel-table .col-flow { min-width: 180px; }
    .net-panel-table .col-proto { min-width: 50px; }
    .net-panel-table .col-port { min-width: 60px; }
    .net-panel-table .col-agent { min-width: 100px; }
    .net-panel-table .col-query { min-width: 120px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
    .net-panel-table .col-bytes { min-width: 70px; }
    .net-panel-table .group-count { background: var(--accent); color: var(--bg-dark); padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.75rem; font-weight: 600; cursor: pointer; margin-left: 0.25rem; }
    .net-panel-table .group-count:hover { opacity: 0.9; }
    .net-panel-table tr.group-children { display: none; background: var(--bg-hover); }
    .net-panel-table tr.group-children.visible { display: table-row; }
    .net-panel-table tr.group-children td { padding: 0.25rem 0.5rem; font-size: 0.8rem; border-top: none; }
    .log-group-badge { background: var(--accent); color: var(--bg-dark); padding: 0.15rem 0.5rem; border-radius: 10px; font-size: 0.75rem; font-weight: 600; margin-left: 0.5rem; cursor: pointer; }
    .log-group-badge:hover { opacity: 0.9; }
    .telemetry-section { padding: 1.5rem 2rem; }
    .telemetry-section h2 { margin-bottom: 1rem; font-size: 1.2rem; }
    .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 1.5rem; margin-bottom: 1.5rem; }
    .chart-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem; }
    .chart-card h3 { font-size: 0.95rem; margin-bottom: 0.75rem; color: var(--text-muted); }
    .chart-container { position: relative; height: 220px; }
    .chart-container-tall { height: 280px; }
    .chart-card-wide { grid-column: 1 / -1; }
    .net-charts-main { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
    .net-panel-table .col-details { max-width: 320px; overflow: hidden; text-overflow: ellipsis; }
    .net-panel-table .cat-pill {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 500;
    }
    .net-panel-table .btn-detail {
      background: none;
      border: none;
      color: var(--accent);
      cursor: pointer;
      font-size: 0.75rem;
      padding: 0;
    }
    .net-panel-table .btn-detail:hover { text-decoration: underline; }
    .net-row-detail {
      display: none;
      padding: 0.75rem;
      background: var(--bg-dark);
      font-size: 0.8rem;
      white-space: pre-wrap;
      word-break: break-all;
      border-top: 1px solid var(--border);
    }
    .net-row-detail.show { display: table-cell; }
    .net-filter-row { margin-bottom: 1rem; }
    .net-filter-row input[type="text"] {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.4rem 0.75rem;
      border-radius: var(--radius);
      font-size: 0.9rem;
      min-width: 140px;
    }
    .net-panel-table .empty-state { text-align: center; padding: 2rem; color: var(--text-muted); }
    #net-log-detail-modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; align-items: center; justify-content: center; }
    #net-log-detail-modal .modal-inner { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; max-width: 92%; max-height: 88%; overflow: hidden; padding: 0; font-family: monospace; font-size: 0.85rem; display: flex; flex-direction: column; }
    #net-log-detail-modal .modal-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
    #net-log-detail-modal .modal-tabs { display: flex; gap: 0.25rem; flex-wrap: wrap; }
    #net-log-detail-modal .modal-tab { padding: 0.4rem 0.8rem; cursor: pointer; background: var(--bg-hover); border: 1px solid var(--border); border-radius: var(--radius); color: var(--text-muted); font-size: 0.8rem; }
    #net-log-detail-modal .modal-tab:hover { color: var(--text); }
    #net-log-detail-modal .modal-tab.active { background: var(--accent); color: var(--bg-dark); border-color: var(--accent); }
    #net-log-detail-modal .modal-body { padding: 1rem 1.5rem; overflow: auto; flex: 1; white-space: pre-wrap; word-break: break-word; }
    #net-log-detail-modal .modal-body table { border-collapse: collapse; width: 100%; margin: 0.5rem 0; font-size: 0.85rem; }
    #net-log-detail-modal .modal-body th, #net-log-detail-modal .modal-body td { padding: 0.35rem 0.75rem; text-align: left; border: 1px solid var(--border); }
    #net-log-detail-modal .modal-body th { color: var(--text-muted); }
    #net-log-detail-modal .detail-block { margin-bottom: 1rem; }
    #net-log-detail-modal .detail-block h4 { font-size: 0.9rem; margin-bottom: 0.5rem; color: var(--accent); }
    .net-charts-title { font-size: 1rem; margin: 1rem 0 0.75rem; color: var(--text-muted); }
    .net-charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .traffic-overview {
      display: grid;
      grid-template-columns: auto 1fr auto;
      align-items: center;
      gap: 1.5rem;
      padding: 1.25rem 1.5rem;
      background: linear-gradient(135deg, var(--bg-card) 0%, #1a1a24 100%);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }
    .traffic-overview .traffic-metrics {
      display: flex;
      gap: 2rem;
      flex-wrap: wrap;
      align-items: baseline;
    }
    .traffic-overview .traffic-metric {
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
    }
    .traffic-overview .traffic-metric .value {
      font-size: 1.75rem;
      font-weight: 700;
      color: var(--accent);
      font-family: 'JetBrains Mono', monospace;
    }
    .traffic-overview .traffic-metric .label {
      font-size: 0.75rem;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .traffic-overview .traffic-sparkline {
      min-width: 200px;
      height: 48px;
      flex: 1;
      max-width: 320px;
    }
    .traffic-overview .traffic-live {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--success);
      font-size: 0.85rem;
      font-weight: 500;
    }
    .traffic-overview .traffic-live::before {
      content: "";
      width: 8px;
      height: 8px;
      background: currentColor;
      border-radius: 50%;
      animation: pulse 1.5s infinite;
    }
    .heatmap-hour {
      display: flex;
      align-items: flex-end;
      gap: 2px;
      height: 56px;
      margin-top: 0.5rem;
    }
    .heatmap-hour .bar {
      flex: 1;
      min-width: 4px;
      background: var(--accent);
      border-radius: 2px 2px 0 0;
      transition: background 0.2s;
    }
    .heatmap-hour .bar:hover { background: var(--accent-dim); }
    .net-panel-table tr.proto-TCP .col-proto { color: #3b82f6; font-weight: 600; }
    .net-panel-table tr.proto-UDP .col-proto { color: #8b5cf6; font-weight: 600; }
    .net-panel-table tr.proto-DNS .col-proto { color: #22c55e; font-weight: 600; }
    .net-panel-table tr.proto-ICMP .col-proto { color: #eab308; font-weight: 600; }
    .net-panel-table .flow-cell { white-space: nowrap; font-size: 0.8rem; }
    .net-panel-table .flow-cell .arrow { color: var(--text-muted); margin: 0 0.25rem; }
    .net-panel-table .flow-cell .src-dst { color: var(--accent); }
    .loading-state { display: flex; align-items: center; justify-content: center; padding: 2rem; color: var(--text-muted); gap: 0.5rem; }
    .loading-state::before { content: ""; width: 20px; height: 20px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .stat-updated { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }
    .service-section { padding: 1.5rem 2rem; }
    .service-section h2 { margin-bottom: 1rem; font-size: 1.2rem; }
    .service-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .service-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem; }
    .service-card h3 { font-size: 0.9rem; color: var(--text-muted); margin-bottom: 0.5rem; }
    .service-card .value { font-size: 1.25rem; font-weight: 600; color: var(--accent); font-family: 'JetBrains Mono', monospace; }
    .service-card .value.ok { color: var(--success); }
    .service-card .value.warn { color: var(--warning); }
    .service-card .value.err { color: var(--danger); }
    .service-metrics pre { background: var(--bg-dark); padding: 1rem; border-radius: var(--radius); overflow: auto; font-size: 0.75rem; max-height: 200px; }
    .service-metrics a { color: var(--accent); }
    .pagination-bar { display: flex; align-items: center; color: var(--text-muted); font-size: 0.9rem; }
    .pagination-bar button { background: var(--bg-hover); color: var(--text); border: 1px solid var(--border); padding: 0.35rem 0.75rem; border-radius: var(--radius); cursor: pointer; }
    .pagination-bar button:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
    .pagination-bar button:disabled { opacity: 0.5; cursor: not-allowed; }
  </style>
</head>
<body>
  <header class="header">
    <div>
      <h1>OSSEC / Wazuh Log Viewer</h1>
      <span class="live-badge">LIVE</span>
    </div>
    <div class="stats" id="stats">
      <span class="stat">Łącznie: <strong id="stat-total">0</strong></span>
      <span class="stat">Logi sieciowe: <strong id="stat-network">0</strong></span>
      <span class="stat">Agenty: <strong id="stat-agents">0</strong></span>
      <span class="stat" id="stat-alerts-wrap" title="Critical/High w ostatniej godzinie" style="display:none;">⚠️ Alerty: <strong id="stat-alerts">0</strong></span>
      <span class="stat stat-updated" id="stat-updated" title="Ostatnia aktualizacja danych">—</span>
    </div>
  </header>
  <div class="tabs">
    <div class="tab active" data-tab="all">Wszystkie logi</div>
    <div class="tab" data-tab="network">🌐 Logi sieciowe</div>
    <div class="tab" data-tab="telemetry">📊 Telemetria</div>
    <div class="tab" data-tab="service">🔧 Serwis</div>
  </div>
  <div class="filters" id="filters-all">
    <select id="filter-category">
      <option value="">Wszystkie kategorie</option>
    </select>
    <select id="filter-severity">
      <option value="">Wszystkie severity</option>
      <option value="info">Info</option>
      <option value="low">Low</option>
      <option value="medium">Medium</option>
      <option value="high">High</option>
      <option value="critical">Critical</option>
    </select>
    <input type="text" id="filter-agent" placeholder="Filtruj po agencie..." style="min-width: 180px;">
    <input type="text" id="filter-search" placeholder="Szukaj w logach (pełny tekst)..." style="min-width: 200px;" title="Skrót: /">
    <select id="filter-time" title="Zakres czasowy">
      <option value="">Wszystkie</option>
      <option value="1">Ostatnia 1 h</option>
      <option value="6">Ostatnie 6 h</option>
      <option value="24">Ostatnie 24 h</option>
      <option value="168">Ostatnie 7 d</option>
    </select>
    <label title="Łączy wpisy o tej samej kategorii, regule i agencie"><input type="checkbox" id="group-same" checked> Grupuj podobne</label>
    <button onclick="applyFilters()" style="background: var(--accent); color: var(--bg-dark); border: none; padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer; font-weight: 500;">Filtruj</button>
    <button type="button" id="btn-refresh" style="background: var(--bg-hover); color: var(--text); border: 1px solid var(--border); padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer; font-weight: 500;">🔄 Odśwież</button>
    <button type="button" id="btn-export-json" style="background: var(--bg-hover); color: var(--accent); border: 1px solid var(--accent); padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer; font-weight: 500;">📥 JSON</button>
    <button type="button" id="btn-export-csv" style="background: var(--bg-hover); color: var(--accent); border: 1px solid var(--accent); padding: 0.5rem 1rem; border-radius: var(--radius); cursor: pointer; font-weight: 500;">📥 CSV</button>
  </div>
  <div class="section active" id="section-all">
    <div class="service-top-rules net-table-card" style="margin: 0 2rem 1rem; max-width: 480px;">
      <h3>📋 Najczęstsze reguły</h3>
      <table><thead><tr><th>Reguła</th><th>Liczba</th></tr></thead><tbody id="top-rules-body"></tbody></table>
    </div>
    <div id="pagination-all" class="pagination-bar" style="display: none; padding: 0.5rem 2rem; gap: 0.75rem; align-items: center; flex-wrap: wrap;"></div>
    <div class="logs-container" id="logs"></div>
  </div>
  <div class="section network-section" id="section-network">
    <div class="section-header">
      <h2>🌐 Logi sieciowe</h2>
      <span class="stat">Łącznie: <strong id="network-count">0</strong></span>
    </div>
    <div class="traffic-overview" id="traffic-overview">
      <div class="traffic-metrics">
        <div class="traffic-metric">
          <span class="value" id="traffic-last1h">0</span>
          <span class="label">Ostatnia 1 h</span>
        </div>
        <div class="traffic-metric">
          <span class="value" id="traffic-last24h">0</span>
          <span class="label">Ostatnie 24 h</span>
        </div>
        <div class="traffic-metric">
          <span class="value" id="traffic-bytes">—</span>
          <span class="label">Bajty (suma)</span>
        </div>
      </div>
      <div class="traffic-sparkline" id="traffic-sparkline-wrap">
        <canvas id="traffic-sparkline" aria-label="Sparkline ruchu"></canvas>
      </div>
      <div class="traffic-live" id="traffic-live-badge">LIVE</div>
    </div>
    <div class="chart-card" style="margin-bottom: 1rem;">
      <h3>📈 Aktywność sieciowa wg godziny (wg zakresu)</h3>
      <div class="heatmap-hour" id="heatmap-hour"></div>
      <div style="display: flex; justify-content: space-between; font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem;">
        <span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>24:00</span>
      </div>
    </div>
    <div class="net-analytics" id="net-analytics">
      <div class="net-card"><span class="value" id="net-total">0</span><div class="label">Wszystkie</div></div>
      <div class="net-card"><span class="value" id="net-traffic">0</span><div class="label">Ruch sieciowy</div></div>
      <div class="net-card"><span class="value" id="net-firewall">0</span><div class="label">Firewall</div></div>
      <div class="net-card"><span class="value" id="net-logins">0</span><div class="label">Logowania (IP)</div></div>
      <div class="net-card"><span class="value" id="net-flow">0</span><div class="label">Przepływ (eBPF)</div></div>
      <div class="net-card"><span class="value" id="net-dns">0</span><div class="label">Zapytania DNS</div></div>
      <div class="net-card"><span class="value" id="net-bytes">0</span><div class="label">Bajty (łącznie)</div></div>
      <div class="net-card"><span class="value" id="net-tcp">0</span><div class="label">TCP</div></div>
      <div class="net-card"><span class="value" id="net-udp">0</span><div class="label">UDP</div></div>
    </div>
    <div class="net-tables" id="net-tables">
      <div class="net-table-card">
        <h3>📤 Top źródła (SRC)</h3>
        <table><thead><tr><th>IP</th><th>Liczba</th></tr></thead><tbody id="net-top-sources"></tbody></table>
      </div>
      <div class="net-table-card">
        <h3>📥 Top cele (DST)</h3>
        <table><thead><tr><th>IP</th><th>Liczba</th></tr></thead><tbody id="net-top-destinations"></tbody></table>
      </div>
      <div class="net-table-card">
        <h3>🔌 Top porty (DPT)</h3>
        <table><thead><tr><th>Port</th><th>Liczba</th></tr></thead><tbody id="net-top-ports"></tbody></table>
      </div>
      <div class="net-table-card">
        <h3>🤖 Po agencie</h3>
        <table><thead><tr><th>Agent</th><th>Liczba</th></tr></thead><tbody id="net-by-agent"></tbody></table>
      </div>
      <div class="net-table-card">
        <h3>🔍 Top zapytania DNS</h3>
        <table><thead><tr><th>Domena</th><th>Liczba</th></tr></thead><tbody id="net-top-dns"></tbody></table>
      </div>
    </div>
    <h3 class="net-charts-title">📈 Wizualizacje ruchu</h3>
    <div class="net-charts-grid net-charts-main" id="net-charts-grid">
      <div class="chart-card chart-card-wide">
        <h3>Logi sieciowe w czasie (wg zakresu)</h3>
        <div class="chart-container chart-container-tall"><canvas id="chart-net-time"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Protokoły</h3>
        <div class="chart-container"><canvas id="chart-net-protocol"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Top porty (DPT)</h3>
        <div class="chart-container"><canvas id="chart-net-ports"></canvas></div>
      </div>
    </div>
    <div class="net-filters net-filter-row">
      <label>Zakres czasu:</label>
      <select id="net-filter-time" title="Okres danych dla listy i analityki">
        <option value="1">Ostatnia 1 h</option>
        <option value="6">Ostatnie 6 h</option>
        <option value="24" selected>Ostatnie 24 h</option>
        <option value="168">Ostatnie 7 d</option>
      </select>
      <label>Podkategoria:</label>
      <select id="net-filter-type">
        <option value="">Wszystkie</option>
        <option value="traffic">Ruch sieciowy</option>
        <option value="flow">Przepływ (eBPF)</option>
        <option value="ports">Porty nasłuchujące</option>
        <option value="dns">Zapytania DNS</option>
        <option value="firewall">Firewall</option>
        <option value="logins">Logowania (IP)</option>
      </select>
      <label>Źródło (SRC):</label>
      <input type="text" id="net-filter-src" placeholder="np. 10.30.25.35">
      <label>Cel (DST):</label>
      <input type="text" id="net-filter-dst" placeholder="np. 10.30.25.166">
      <label>DNS / Query:</label>
      <input type="text" id="net-filter-query" placeholder="np. google.com">
      <label>Agent:</label>
      <select id="net-filter-agent">
        <option value="">Wszyscy</option>
      </select>
      <label title="Łączy identyczne wpisy (SRC+DST+proto+port+query)"><input type="checkbox" id="net-group-same" checked> Grupuj podobne</label>
      <button onclick="applyNetworkFilters()" style="background: var(--accent); color: var(--bg-dark); border: none; padding: 0.4rem 0.8rem; border-radius: var(--radius); cursor: pointer; font-weight: 500;">Filtruj</button>
      <button type="button" id="net-export-csv" style="background: var(--bg-hover); color: var(--accent); border: 1px solid var(--accent); padding: 0.4rem 0.8rem; border-radius: var(--radius); cursor: pointer; font-weight: 500;">📥 Eksport CSV</button>
      <span class="stat" style="margin-left:0.5rem">Wyników: <strong id="net-result-count">0</strong></span>
    </div>
    <div id="pagination-network" class="pagination-bar" style="display: none; padding: 0.5rem 2rem; margin-bottom: 0.5rem;"></div>
    <div class="net-panel-table-wrap">
      <table class="net-panel-table" id="net-panel-table">
        <thead>
          <tr>
            <th class="col-time sortable" data-sort="time">Czas <span class="sort-icon"></span></th>
            <th class="col-cat sortable" data-sort="category">Kategoria <span class="sort-icon"></span></th>
            <th class="col-src sortable" data-sort="src">Źródło (SRC) <span class="sort-icon"></span></th>
            <th class="col-dst sortable" data-sort="dst">Cel (DST) <span class="sort-icon"></span></th>
            <th class="col-flow">Przepływ</th>
            <th class="col-proto sortable" data-sort="proto">Proto <span class="sort-icon"></span></th>
        <th class="col-port sortable" data-sort="port">Port <span class="sort-icon"></span></th>
        <th class="col-query sortable" data-sort="query">DNS / Query <span class="sort-icon"></span></th>
        <th class="col-bytes sortable" data-sort="bytes">Bajty <span class="sort-icon"></span></th>
        <th class="col-agent sortable" data-sort="agent">Agent <span class="sort-icon"></span></th>
        <th class="col-details">Szczegóły</th>
          </tr>
        </thead>
        <tbody id="net-table-body"></tbody>
      </table>
    </div>
    <div id="net-log-detail-modal" onclick="closeNetDetail(event)">
      <div class="modal-inner" id="net-log-detail-content" onclick="event.stopPropagation()">
        <div class="modal-header">
          <div class="modal-tabs">
            <button type="button" class="modal-tab active" data-detail-tab="raw">Pełny log (raw)</button>
            <button type="button" class="modal-tab" data-detail-tab="meta">Metadane sieciowe</button>
            <button type="button" class="modal-tab" data-detail-tab="json">Pełny JSON</button>
          </div>
          <div style="display: flex; gap: 0.5rem;">
            <button type="button" id="net-detail-copy" style="background: var(--accent); color: var(--bg-dark); border: none; padding: 0.4rem 0.8rem; border-radius: var(--radius); cursor: pointer; font-size: 0.85rem;">Kopiuj</button>
            <button type="button" onclick="document.getElementById('net-log-detail-modal').style.display='none'" style="background: var(--bg-hover); color: var(--text); border: 1px solid var(--border); padding: 0.4rem 0.8rem; border-radius: var(--radius); cursor: pointer; font-size: 0.85rem;">Zamknij</button>
          </div>
        </div>
        <div class="modal-body" id="net-log-detail-body"></div>
      </div>
    </div>
  </div>
  <div class="section telemetry-section" id="section-telemetry">
    <div class="section-header" style="flex-wrap: wrap; gap: 0.75rem;">
      <h2>📊 Telemetria</h2>
      <label style="display: flex; align-items: center; gap: 0.5rem;">Zakres: <select id="telemetry-hours" style="background: var(--bg-card); border: 1px solid var(--border); color: var(--text); padding: 0.35rem 0.5rem; border-radius: var(--radius);">
        <option value="6">6 h</option>
        <option value="12">12 h</option>
        <option value="24" selected>24 h</option>
        <option value="48">48 h</option>
        <option value="168">7 d</option>
      </select></label>
      <button type="button" id="telemetry-apply-range" style="background: var(--accent); color: var(--bg-dark); border: none; padding: 0.35rem 0.75rem; border-radius: var(--radius); cursor: pointer;">Pobierz</button>
    </div>
    <div id="telemetry-loading" class="loading-state" style="display:none;">Ładowanie telemetrii…</div>
    <div class="chart-grid" id="telemetry-charts">
      <div class="chart-card">
        <h3>Logi w czasie</h3>
        <div class="chart-container"><canvas id="chart-time-total"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Logi sieciowe w czasie</h3>
        <div class="chart-container"><canvas id="chart-time-network"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Kategorie</h3>
        <div class="chart-container"><canvas id="chart-categories"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Severity</h3>
        <div class="chart-container"><canvas id="chart-severity"></canvas></div>
      </div>
      <div class="chart-card">
        <h3>Typy logów sieciowych</h3>
        <div class="chart-container"><canvas id="chart-network-types"></canvas></div>
      </div>
    </div>
  </div>
  <div class="section service-section" id="section-service">
    <h2>🔧 Serwis – stan zdrowia i metryki</h2>
    <div id="service-loading" class="loading-state" style="display:none;">Ładowanie…</div>
    <div id="service-content" style="display:none;">
      <div class="service-grid" id="service-health-grid"></div>
      <div class="service-card service-metrics">
        <h3>Metryki Prometheus</h3>
        <p>Endpoint dla monitoringu (Grafana, Zabbix): <a href="/metrics" target="_blank" rel="noopener">GET /metrics</a></p>
        <p><button type="button" id="service-refresh-btn" style="background: var(--accent); color: var(--bg-dark); border: none; padding: 0.4rem 0.8rem; border-radius: var(--radius); cursor: pointer; font-size: 0.85rem;">Odśwież dane</button></p>
      </div>
    </div>
  </div>

  <script>
    let allLogs = [];
    let networkLogs = [];
    let logsOffset = 0;
    let logsTotal = 0;
    const LOGS_PAGE_SIZE = 200;
    let networkLogsOffset = 0;
    let networkLogsTotal = 0;
    const NETWORK_PAGE_SIZE = 500;
    const logsEl = document.getElementById('logs');
    const statTotal = document.getElementById('stat-total');
    const statNetwork = document.getElementById('stat-network');
    const statAgents = document.getElementById('stat-agents');
    const networkCountEl = document.getElementById('network-count');
    const filterCategory = document.getElementById('filter-category');
    const filterSeverity = document.getElementById('filter-severity');
    const filterAgent = document.getElementById('filter-agent');
    const filterSearch = document.getElementById('filter-search');
    const filterTime = document.getElementById('filter-time');

    function isNetworkLog(log) {
      const cat = log._category || {};
      const tags = cat.tags || [];
      return tags.includes('network') || ['network_traffic','firewall','login_history','network_flow','netstat_ports','dns_query'].includes(cat.name);
    }

    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('section-' + tab.dataset.tab).classList.add('active');
        document.getElementById('filters-all').style.display = tab.dataset.tab === 'all' ? 'flex' : 'none';
        if (tab.dataset.tab === 'network') { fetchNetworkLogs(); }
        if (tab.dataset.tab === 'telemetry') { fetchTelemetry(); }
        if (tab.dataset.tab === 'service') { fetchServiceState(); }
        if (tab.dataset.tab !== 'network') { destroyNetworkCharts(); }
      });
    });
    document.getElementById('group-same')?.addEventListener('change', applyFilters);
    document.getElementById('net-group-same')?.addEventListener('change', applyNetworkFilters);

    function renderLogs(logs, targetEl, groupSame) {
      targetEl = targetEl || logsEl;
      if (!logs.length) {
        targetEl.innerHTML = '<div class="empty-state">Brak logów spełniających kryteria</div>';
        return;
      }
      const groups = groupSame ? groupLogs(logs, getLogGroupKey) : logs.map(l => [l]);
      targetEl.innerHTML = groups.map(group => {
        const log = group[0];
        const count = group.length;
        const cat = log._category || {};
        const agent = log.agent || {};
        const agentName = typeof agent === 'object' ? (agent.name || agent.id || '-') : '-';
        const ts = count > 1 ? (group[group.length - 1].timestamp || '') + ' … ' + (group[0].timestamp || '') : (log.timestamp || '-');
        const fullLog = (log.full_log || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const sevClass = 'severity-' + (cat.severity || 'info');
        const countBadge = count > 1 ? `<span class="log-group-badge" onclick="toggleLogGroup(this)">×${count}</span>` : '';
        const childEntries = count > 1 ? group.slice(1).map(g => {
          const t = g.timestamp || '-';
          const fl = (g.full_log || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
          return `<div class="log-entry log-group-child" style="display:none; margin-left:1rem; border-left:2px solid var(--border); padding-left:0.5rem;"><div class="meta"><span>🕐 ${t}</span></div><div class="full-log">${fl}</div></div>`;
        }).join('') : '';
        return `
          <div class="log-entry log-group" data-id="${log.id || ''}">
            <div class="meta">
              <span class="category-badge" style="background: ${cat.color}22; color: ${cat.color}">${cat.icon || ''} ${cat.display_name || 'Inne'}</span>
              <span class="${sevClass}">${cat.severity || 'info'}</span>
              <span>🕐 ${ts}</span>${countBadge}
              <span>🤖 ${agentName}</span>
              ${log.rule && log.rule.description ? `<span>📋 ${log.rule.description}</span>` : ''}
            </div>
            <div class="full-log">${fullLog}</div>
            <button class="expand-btn" onclick="toggleExpand(this)">Pokaż więcej</button>
            ${childEntries}
          </div>
        `;
      }).join('');
    }
    function toggleLogGroup(btn) {
      const entry = btn.closest('.log-group');
      if (!entry) return;
      const children = entry.querySelectorAll('.log-group-child');
      const visible = children[0] && children[0].style.display !== 'none';
      children.forEach(c => { c.style.display = visible ? 'none' : 'block'; });
    }

    let networkCharts = {};
    function destroyNetworkCharts() {
      ['net-time', 'net-protocol', 'net-ports'].forEach(id => {
        if (networkCharts[id]) { networkCharts[id].destroy(); networkCharts[id] = null; }
      });
    }
    function drawNetworkCharts(analytics, telemetry) {
      destroyNetworkCharts();
      const chartOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#71717a' } } }, scales: { x: { ticks: { color: '#71717a', maxTicksLimit: 12 } }, y: { ticks: { color: '#71717a' } } } };
      const labels = (telemetry && telemetry.time_labels) || [];
      const netSeries = (telemetry && telemetry.time_network) || [];
      const elTime = document.getElementById('chart-net-time');
      if (elTime) {
        networkCharts['net-time'] = new Chart(elTime, {
          type: 'line',
          data: { labels, datasets: [{ label: 'Logi sieciowe', data: netSeries, borderColor: '#0ea5e9', backgroundColor: 'rgba(14,165,233,0.15)', fill: true, tension: 0.3 }] },
          options: chartOpts
        });
      }
      const byProto = (analytics && analytics.by_protocol) || {};
      const protoKeys = Object.keys(byProto).filter(k => byProto[k] > 0);
      const protoVals = protoKeys.map(k => byProto[k]);
      const elProto = document.getElementById('chart-net-protocol');
      if (elProto) {
        networkCharts['net-protocol'] = new Chart(elProto, {
          type: 'doughnut',
          data: {
            labels: protoKeys.length ? protoKeys : ['Brak'],
            datasets: [{ data: protoVals.length ? protoVals : [1], backgroundColor: ['#0ea5e9', '#8b5cf6', '#22c55e', '#eab308', '#ef4444', '#f97316'] }]
          },
          options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#71717a' } } } }
        });
      }
      const topPorts = (analytics && analytics.top_ports) || [];
      const elPorts = document.getElementById('chart-net-ports');
      if (elPorts) {
        networkCharts['net-ports'] = new Chart(elPorts, {
          type: 'bar',
          data: {
            labels: topPorts.slice(0, 15).map(r => r.key),
            datasets: [{ label: 'Liczba', data: topPorts.slice(0, 15).map(r => r.count), backgroundColor: '#06b6d4' }]
          },
          options: chartOpts
        });
      }
    }

    function updateTrafficOverview(analytics, telemetry) {
      const el1h = document.getElementById('traffic-last1h');
      const el24h = document.getElementById('traffic-last24h');
      const elBytes = document.getElementById('traffic-bytes');
      const netSeries = (telemetry && telemetry.time_network) || [];
      const last24h = netSeries.reduce((s, v) => s + (v || 0), 0);
      const last1h = netSeries.length >= 12 ? netSeries.slice(-12).reduce((s, v) => s + (v || 0), 0) : last24h;
      if (el1h) el1h.textContent = last1h;
      if (el24h) el24h.textContent = last24h;
      const bytes = analytics && analytics.total_bytes;
      if (elBytes) elBytes.textContent = bytes != null ? (bytes >= 1048576 ? (bytes/1048576).toFixed(1) + ' MB' : bytes >= 1024 ? (bytes/1024).toFixed(1) + ' KB' : bytes) : '—';
      drawTrafficSparkline(netSeries.slice(-24));
      drawHeatmapByHour(netSeries);
    }
    function drawTrafficSparkline(data) {
      const canvas = document.getElementById('traffic-sparkline');
      if (!canvas || !data.length) return;
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.parentElement.offsetWidth || 200;
      const h = 48;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = w + 'px';
      canvas.style.height = h + 'px';
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      const max = Math.max(...data, 1);
      const pad = 2;
      const chartW = w - pad * 2;
      const chartH = h - pad * 2;
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      data.forEach((v, i) => {
        const x = pad + (i / (data.length - 1 || 1)) * chartW;
        const y = pad + chartH - (v / max) * chartH;
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
    function drawHeatmapByHour(netSeries) {
      const wrap = document.getElementById('heatmap-hour');
      if (!wrap) return;
      const bucketsPerHour = 12;
      const hours = 24;
      const bars = [];
      for (let i = 0; i < hours; i++) {
        const start = i * bucketsPerHour;
        const chunk = netSeries.slice(start, start + bucketsPerHour);
        bars.push(chunk.reduce((s, v) => s + (v || 0), 0));
      }
      const maxBar = Math.max(...bars, 1);
      wrap.innerHTML = bars.map((v, i) => {
        const pct = Math.round((v / maxBar) * 100);
        return '<div class="bar" style="height:' + (pct || 2) + '%" title="' + i + ':00–' + (i+1) + ':00 — ' + v + ' zdarzeń"></div>';
      }).join('');
    }

    async function fetchNetworkAnalytics() {
      const timeEl = document.getElementById('net-filter-time');
      const hours = timeEl ? (parseFloat(timeEl.value) || 24) : 24;
      try {
        const [resA, resT] = await Promise.all([
          fetch('/api/network/analytics?hours=' + encodeURIComponent(hours)),
          fetch('/api/telemetry?bucket_minutes=5&hours=' + encodeURIComponent(hours))
        ]);
        const a = await resA.json();
        let t = {};
        try { t = await resT.json(); } catch (_) {}
        updateTrafficOverview(a, t);
        document.getElementById('net-total').textContent = a.total || 0;
        document.getElementById('net-traffic').textContent = a.by_type && a.by_type['Ruch sieciowy'] != null ? a.by_type['Ruch sieciowy'] : 0;
        document.getElementById('net-firewall').textContent = a.by_type && a.by_type['Firewall'] != null ? a.by_type['Firewall'] : 0;
        document.getElementById('net-logins').textContent = a.by_type && a.by_type['Logowania (IP)'] != null ? a.by_type['Logowania (IP)'] : 0;
        document.getElementById('net-flow').textContent = a.by_type && a.by_type['Przepływ (eBPF)'] != null ? a.by_type['Przepływ (eBPF)'] : 0;
        document.getElementById('net-dns').textContent = a.by_type && a.by_type['Zapytania DNS'] != null ? a.by_type['Zapytania DNS'] : 0;
        document.getElementById('net-bytes').textContent = a.total_bytes != null ? (a.total_bytes >= 1048576 ? (a.total_bytes/1048576).toFixed(1) + ' MB' : a.total_bytes >= 1024 ? (a.total_bytes/1024).toFixed(1) + ' KB' : a.total_bytes) : 0;
        document.getElementById('net-tcp').textContent = a.by_protocol && a.by_protocol['TCP'] != null ? a.by_protocol['TCP'] : 0;
        document.getElementById('net-udp').textContent = a.by_protocol && a.by_protocol['UDP'] != null ? a.by_protocol['UDP'] : 0;
        const fillTable = (id, rows, keyLabel) => {
          const tbody = document.getElementById(id);
          if (!tbody) return;
          tbody.innerHTML = (rows || []).map(r => `<tr><td>${keyLabel ? r.key : r.key}</td><td>${r.count}</td></tr>`).join('') || '<tr><td colspan="2">Brak danych</td></tr>';
        };
        fillTable('net-top-sources', a.top_sources);
        fillTable('net-top-destinations', a.top_destinations);
        fillTable('net-top-ports', a.top_ports);
        fillTable('net-by-agent', a.by_agent);
        fillTable('net-top-dns', a.top_dns_queries || []);
        const agentSelect = document.getElementById('net-filter-agent');
        if (agentSelect && a.by_agent && Array.isArray(a.by_agent)) {
          const opts = a.by_agent.map(r => r.key).sort();
          const current = agentSelect.value;
          agentSelect.innerHTML = '<option value="">Wszyscy</option>' + opts.map(o => `<option value="${o}">${o}</option>`).join('');
          agentSelect.value = current || '';
        }
        drawNetworkCharts(a, t);
      } catch (e) {}
    }

    function getCurrentFilteredNetworkLogs() {
      const typeFilter = (document.getElementById('net-filter-type') || {}).value;
      const agentFilter = (document.getElementById('net-filter-agent') || {}).value;
      const srcFilter = (document.getElementById('net-filter-src') || {}).value.trim().toLowerCase();
      const dstFilter = (document.getElementById('net-filter-dst') || {}).value.trim().toLowerCase();
      const queryFilter = (document.getElementById('net-filter-query') || {}).value.trim().toLowerCase();
      let list = [...(networkLogs || [])];
      if (typeFilter) list = list.filter(l => networkSubtype(l) === typeFilter);
      if (agentFilter) {
        list = list.filter(l => {
          const a = l.agent;
          const aname = (typeof a === 'object' && a !== null) ? (a.name || a.id) : (typeof a === 'string' ? a : '');
          return String(aname || '') === agentFilter;
        });
      }
      if (srcFilter) list = list.filter(l => ((l._network_meta || {}).src || '').toLowerCase().includes(srcFilter));
      if (dstFilter) list = list.filter(l => ((l._network_meta || {}).dst || '').toLowerCase().includes(dstFilter));
      if (queryFilter) list = list.filter(l => ((l._network_meta || {}).query || '').toLowerCase().includes(queryFilter));
      return sortNetworkLogs(list);
    }
    function exportNetworkCSV() {
      const list = getCurrentFilteredNetworkLogs();
      const headers = ['timestamp', 'category', 'severity', 'src', 'dst', 'proto', 'sport', 'dport', 'query', 'bytes', 'agent', 'full_log'];
      const escapeCsv = v => {
        const s = (v == null ? '' : String(v));
        if (/[",\\n\\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
        return s;
      };
      const rows = list.slice(0, 10000).map(log => {
        const m = log._network_meta || {};
        const c = log._category || {};
        const a = log.agent || {};
        const agentName = typeof a === 'object' ? (a.name || a.id || '') : a;
        return [log.timestamp || '', c.display_name || '', c.severity || '', m.src || '', m.dst || '', m.proto || '', m.sport ?? '', m.dport ?? '', m.query || '', m.bytes ?? '', agentName, log.full_log || ''].map(escapeCsv).join(',');
      });
      const csv = [headers.join(','), ...rows].join('\\n');
      const blob = new Blob(['\\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'network-logs-' + new Date().toISOString().slice(0, 19).replace(/:/g, '-') + '.csv';
      a.click();
      URL.revokeObjectURL(a.href);
    }
    document.getElementById('net-export-csv')?.addEventListener('click', exportNetworkCSV);

    const chartDefaults = {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { labels: { color: '#71717a' } } },
      scales: { x: { ticks: { color: '#71717a', maxTicksLimit: 12 } }, y: { ticks: { color: '#71717a' } } }
    };
    let telemetryCharts = {};

    function destroyChart(id) {
      if (telemetryCharts[id]) { telemetryCharts[id].destroy(); telemetryCharts[id] = null; }
    }

    async function fetchTelemetry() {
      const loadingEl = document.getElementById('telemetry-loading');
      const chartsEl = document.getElementById('telemetry-charts');
      const hoursEl = document.getElementById('telemetry-hours');
      const hours = hoursEl ? (parseFloat(hoursEl.value) || 24) : 24;
      if (loadingEl) loadingEl.style.display = 'flex';
      if (chartsEl) chartsEl.style.opacity = '0.5';
      try {
        const res = await fetch('/api/telemetry?bucket_minutes=5&hours=' + encodeURIComponent(hours));
        const t = await res.json();
        const labels = t.time_labels || [];
        const totalData = t.time_total || [];
        const networkData = t.time_network || [];
        const byCat = t.by_category || {};
        const bySev = t.by_severity || {};
        const netTypes = t.network_by_type || {};

        destroyChart('time-total');
        telemetryCharts['time-total'] = new Chart(document.getElementById('chart-time-total'), {
          type: 'line',
          data: {
            labels, datasets: [{ label: 'Logi', data: totalData, borderColor: '#06b6d4', backgroundColor: 'rgba(6,182,212,0.1)', fill: true, tension: 0.3 }]
          },
          options: { ...chartDefaults }
        });

        destroyChart('time-network');
        telemetryCharts['time-network'] = new Chart(document.getElementById('chart-time-network'), {
          type: 'line',
          data: {
            labels, datasets: [{ label: 'Logi sieciowe', data: networkData, borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.1)', fill: true, tension: 0.3 }]
          },
          options: { ...chartDefaults }
        });

        const catKeys = Object.keys(byCat);
        const catVals = Object.values(byCat);
        const palette = ['#06b6d4','#8b5cf6','#22c55e','#eab308','#ef4444','#0ea5e9','#6366f1','#0891b2','#a855f7','#f59e0b'];
        const catColors = catKeys.map((_, i) => palette[i % palette.length]);
        destroyChart('categories');
        telemetryCharts['categories'] = new Chart(document.getElementById('chart-categories'), {
          type: 'doughnut',
          data: {
            labels: catKeys,
            datasets: [{ data: catVals, backgroundColor: catColors }]
          },
          options: { ...chartDefaults }
        });

        const sevKeys = Object.keys(bySev);
        const sevVals = Object.values(bySev);
        destroyChart('severity');
        telemetryCharts['severity'] = new Chart(document.getElementById('chart-severity'), {
          type: 'bar',
          data: {
            labels: sevKeys,
            datasets: [{ label: 'Liczba', data: sevVals, backgroundColor: '#06b6d4' }]
          },
          options: { ...chartDefaults }
        });

        const netKeys = Object.keys(netTypes);
        const netVals = Object.values(netTypes);
        destroyChart('network-types');
        telemetryCharts['network-types'] = new Chart(document.getElementById('chart-network-types'), {
          type: 'doughnut',
          data: {
            labels: netKeys.length ? netKeys : ['Brak danych'],
            datasets: [{ data: netVals.length ? netVals : [1], backgroundColor: ['#0ea5e9','#8b5cf6','#ea580c','#6366f1','#22c55e'] }]
          },
          options: { ...chartDefaults }
        });
      } catch (e) {}
      if (loadingEl) loadingEl.style.display = 'none';
      if (chartsEl) chartsEl.style.opacity = '';
    }

    function networkSubtype(log) {
      return log._network_subtype || (log._category && log._category.name === 'network_traffic' ? 'traffic' : log._category && log._category.name === 'network_flow' ? 'flow' : log._category && log._category.name === 'netstat_ports' ? 'ports' : log._category && log._category.name === 'dns_query' ? 'dns' : log._category && log._category.name === 'firewall' ? 'firewall' : log._category && log._category.name === 'login_history' ? 'logins' : 'other');
    }

    function getNetworkGroupKey(log) {
      const cat = log._category || {};
      const meta = log._network_meta || {};
      const agent = log.agent || {};
      const agentName = typeof agent === 'object' ? (agent.name || agent.id || '') : '';
      return [cat.name || '', meta.src || '', meta.dst || '', meta.proto || '', String(meta.dport ?? ''), meta.query || '', agentName].join('|');
    }

    function getLogGroupKey(log) {
      const cat = log._category || {};
      const rule = log.rule || {};
      const desc = (rule.description || '').substring(0, 120);
      const agent = log.agent || {};
      const agentName = typeof agent === 'object' ? (agent.name || agent.id || '') : '';
      return [cat.name || '', desc, agentName].join('|');
    }

    function groupLogs(logs, getKey) {
      const map = new Map();
      for (const log of logs) {
        const k = getKey(log);
        if (!map.has(k)) map.set(k, []);
        map.get(k).push(log);
      }
      return Array.from(map.values());
    }

    let networkSortBy = 'time';
    let networkSortDir = 'desc';

    function getNetworkSortKey(log, key) {
      const meta = log._network_meta || {};
      const agent = log.agent || {};
      switch (key) {
        case 'time': return log.timestamp || '';
        case 'category': return (log._category || {}).display_name || '';
        case 'src': return meta.src || '';
        case 'dst': return meta.dst || '';
        case 'proto': return meta.proto || '';
        case 'port': return meta.dport != null ? meta.dport : -1;
        case 'query': return meta.query || '';
        case 'bytes': return meta.bytes != null ? meta.bytes : -1;
        case 'agent': return (typeof agent === 'object' && agent !== null) ? (agent.name || agent.id || '') : String(agent || '');
        default: return '';
      }
    }

    function sortNetworkLogs(logs) {
      const dir = networkSortDir === 'asc' ? 1 : -1;
      return [...logs].sort((a, b) => {
        const va = getNetworkSortKey(a, networkSortBy);
        const vb = getNetworkSortKey(b, networkSortBy);
        if (va === vb) return 0;
        const cmp = (typeof va === 'number' && typeof vb === 'number') ? va - vb : String(va).localeCompare(String(vb), undefined, { numeric: true });
        return cmp * dir;
      });
    }

    function setNetworkSort(col) {
      if (networkSortBy === col) networkSortDir = networkSortDir === 'asc' ? 'desc' : 'asc';
      else { networkSortBy = col; networkSortDir = 'desc'; }
      document.querySelectorAll('.net-panel-table th.sortable').forEach(th => {
        th.classList.remove('sorted-asc', 'sorted-desc');
        if (th.dataset.sort === networkSortBy) th.classList.add('sorted-' + networkSortDir);
      });
      applyNetworkFilters();
    }

    function applyNetworkFilters() {
      const typeFilter = (document.getElementById('net-filter-type') || {}).value;
      const agentFilter = (document.getElementById('net-filter-agent') || {}).value;
      const srcFilter = (document.getElementById('net-filter-src') || {}).value.trim().toLowerCase();
      const dstFilter = (document.getElementById('net-filter-dst') || {}).value.trim().toLowerCase();
      const queryFilter = (document.getElementById('net-filter-query') || {}).value.trim().toLowerCase();
      const groupSame = (document.getElementById('net-group-same') || {}).checked;
      let filtered = [...networkLogs];
      if (typeFilter) filtered = filtered.filter(l => networkSubtype(l) === typeFilter);
      if (agentFilter) filtered = filtered.filter(l => {
        const a = l.agent;
        const aname = (typeof a === 'object' && a !== null) ? (a.name || a.id) : (typeof a === 'string' ? a : '');
        return String(aname || '') === agentFilter;
      });
      if (srcFilter) filtered = filtered.filter(l => ((l._network_meta || {}).src || '').toLowerCase().includes(srcFilter));
      if (dstFilter) filtered = filtered.filter(l => ((l._network_meta || {}).dst || '').toLowerCase().includes(dstFilter));
      if (queryFilter) filtered = filtered.filter(l => ((l._network_meta || {}).query || '').toLowerCase().includes(queryFilter));
      filtered = sortNetworkLogs(filtered);
      document.getElementById('net-result-count').textContent = filtered.length;
      renderNetworkTable(filtered.slice(0, 500), groupSame);
    }

    let _netTableData = [];
    let _netDetailCurrentLog = null;
    let _netDetailActiveTab = 'raw';

    function renderNetDetailBody(log, tab) {
      const body = document.getElementById('net-log-detail-body');
      if (!body) return;
      const meta = log._network_meta || {};
      const cat = log._category || {};
      const rule = log.rule || {};
      const agent = log.agent || {};
      const decoder = log.decoder || {};
      if (tab === 'raw') {
        body.textContent = log.full_log || '(brak full_log)';
        return;
      }
      if (tab === 'meta') {
        const rows = [
          ['Kategoria', (cat.display_name || '') + ' (' + (cat.name || '') + ')'],
          ['Severity', cat.severity || '—'],
          ['Agent', typeof agent === 'object' ? (agent.name || agent.id || '—') : String(agent)],
          ['Reguła', (rule.description || rule.id || '—')],
          ['Decoder', typeof decoder === 'object' ? (decoder.name || '—') : '—'],
          ['Źródło (SRC)', meta.src || '—'],
          ['Cel (DST)', meta.dst || '—'],
          ['Protokół', meta.proto || '—'],
          ['Port źródłowy', meta.sport != null ? meta.sport : '—'],
          ['Port docelowy', meta.dport != null ? meta.dport : '—'],
          ['Interfejs', meta.interface || '—'],
          ['Zapytanie DNS', meta.query || '—'],
          ['Bajty', meta.bytes != null ? meta.bytes : '—'],
          ['Proces', meta.process || '—'],
        ];
        body.innerHTML = '<div class="detail-block"><h4>Metadane</h4><table><thead><tr><th>Pole</th><th>Wartość</th></tr></thead><tbody>' +
          rows.map(r => '<tr><td>' + r[0] + '</td><td>' + (r[1] + '').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</td></tr>').join('') + '</tbody></table></div>';
        if (log.full_log) {
          body.innerHTML += '<div class="detail-block"><h4>full_log</h4><pre style="margin:0; white-space: pre-wrap; word-break: break-all;">' + (log.full_log + '').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</pre></div>';
        }
        return;
      }
      if (tab === 'json') {
        try {
          const jsonStr = JSON.stringify(log, null, 2);
          body.textContent = jsonStr;
        } catch (e) {
          body.textContent = '(błąd serializacji: ' + e.message + ')';
        }
      }
    }

    function showNetDetail(idx) {
      const log = _netTableData[idx] || {};
      _netDetailCurrentLog = log;
      _netDetailActiveTab = 'raw';
      document.querySelectorAll('#net-log-detail-modal .modal-tab').forEach(t => {
        t.classList.toggle('active', t.dataset.detailTab === 'raw');
      });
      renderNetDetailBody(log, 'raw');
      const modal = document.getElementById('net-log-detail-modal');
      modal.style.display = 'flex';
    }
    document.querySelectorAll('#net-log-detail-modal .modal-tab').forEach(btn => {
      btn.addEventListener('click', function() {
        if (!_netDetailCurrentLog) return;
        _netDetailActiveTab = this.dataset.detailTab;
        document.querySelectorAll('#net-log-detail-modal .modal-tab').forEach(t => t.classList.toggle('active', t.dataset.detailTab === _netDetailActiveTab));
        renderNetDetailBody(_netDetailCurrentLog, _netDetailActiveTab);
      });
    });
    document.getElementById('net-detail-copy')?.addEventListener('click', function() {
      const body = document.getElementById('net-log-detail-body');
      if (!body) return;
      const text = body.innerText || body.textContent || '';
      navigator.clipboard.writeText(text).then(() => { this.textContent = 'Skopiowano!'; setTimeout(() => { this.textContent = 'Kopiuj'; }, 1500); }).catch(() => {});
    });
    function toggleNetGroup(btn) {
      const row = btn.closest('tr.group-row');
      if (!row) return;
      const gid = row.dataset.groupId;
      const children = document.querySelectorAll(`tr.group-children[data-parent="${gid}"]`);
      const isExpanded = row.classList.contains('group-expanded');
      if (isExpanded) {
        row.classList.remove('group-expanded');
        children.forEach(c => c.classList.remove('visible'));
      } else {
        row.classList.add('group-expanded');
        children.forEach(c => c.classList.add('visible'));
      }
    }
    function closeNetDetail(e) {
      if (e.target.id === 'net-log-detail-modal') document.getElementById('net-log-detail-modal').style.display = 'none';
    }

    function renderNetworkTable(logs, groupSame) {
      const tbody = document.getElementById('net-table-body');
      if (!tbody) return;
      if (!logs.length) {
        tbody.innerHTML = '<tr><td colspan="11" class="empty-state">Brak logów spełniających kryteria</td></tr>';
        return;
      }
      const groups = groupSame ? groupLogs(logs, getNetworkGroupKey) : logs.map(l => [l]);
      const flatList = [];
      for (const group of groups) {
        for (const log of group) flatList.push(log);
      }
      let flatIdx = 0;
      const rows = [];
      for (const group of groups) {
        const log = group[0];
        const count = group.length;
        const cat = log._category || {};
        const agent = log.agent || {};
        const agentName = typeof agent === 'object' ? (agent.name || agent.id || '-') : '-';
        const ts = count > 1 ? (group[group.length - 1].timestamp || '') + ' … ' + (group[0].timestamp || '') : (log.timestamp || '-');
        const meta = log._network_meta || {};
        const src = meta.src || '—';
        const dst = meta.dst || '—';
        const proto = (meta.proto || '—').toUpperCase();
        const protoClass = proto !== '—' ? 'proto-' + proto : '';
        const port = meta.dport != null ? meta.dport : '—';
        const query = meta.query || '—';
        const flowLabel = (src !== '—' && dst !== '—') ? (src + ' → ' + dst) : (src + ' → ' + dst);
        const bytesSum = group.reduce((s, l) => s + ((l._network_meta || {}).bytes || 0), 0);
        const bytesVal = bytesSum > 0 ? (bytesSum >= 1024 ? (bytesSum/1024).toFixed(1) + 'K' : bytesSum) : '—';
        const shortDetail = (log.full_log || '').substring(0, 80) + ((log.full_log || '').length > 80 ? '…' : '');
        const shortEsc = shortDetail.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        const countBadge = count > 1 ? `<span class="group-count" title="Kliknij, aby rozwinąć" onclick="toggleNetGroup(this)">×${count}</span>` : '';
        const groupId = 'g' + flatIdx;
        const startIdx = flatIdx;
        rows.push(`<tr class="group-row ${protoClass}" data-group-id="${groupId}">
          <td class="col-time">${ts}${countBadge}</td>
          <td class="col-cat"><span class="cat-pill" style="background:${cat.color}22;color:${cat.color}">${cat.icon || ''} ${cat.display_name || 'Inne'}</span></td>
          <td class="col-src">${src}</td>
          <td class="col-dst">${dst}</td>
          <td class="col-flow flow-cell"><span class="src-dst">${flowLabel.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span></td>
          <td class="col-proto">${proto}</td>
          <td class="col-port">${port}</td>
          <td class="col-query">${query}</td>
          <td class="col-bytes">${bytesVal}</td>
          <td class="col-agent">${agentName}</td>
          <td class="col-details">${shortEsc} <button class="btn-detail" onclick="showNetDetail(${startIdx})">Pokaż</button></td>
        </tr>`);
        if (count > 1) {
          for (let i = 0; i < group.length; i++) {
            const g = group[i];
            const idx = startIdx + i;
            const t = g.timestamp || '-';
            rows.push(`<tr class="group-children" data-parent="${groupId}"><td colspan="11" style="padding-left:2rem">🕐 ${t} | ${(g.full_log || '').substring(0, 100).replace(/</g, '&lt;')}… <button class="btn-detail" onclick="showNetDetail(${idx})">Pokaż</button></td></tr>`);
          }
        }
        flatIdx += group.length;
      }
      _netTableData = flatList;
      tbody.innerHTML = rows.join('');
      document.querySelectorAll('.net-panel-table th.sortable').forEach(th => {
        th.onclick = () => setNetworkSort(th.dataset.sort);
        th.classList.toggle('sorted-asc', th.dataset.sort === networkSortBy && networkSortDir === 'asc');
        th.classList.toggle('sorted-desc', th.dataset.sort === networkSortBy && networkSortDir === 'desc');
      });
    }

    function updatePaginationNetwork() {
      const el = document.getElementById('pagination-network');
      if (!el) return;
      if (networkLogsTotal <= 0) { el.style.display = 'none'; return; }
      el.style.display = 'flex';
      const from = networkLogsOffset + 1;
      const to = Math.min(networkLogsOffset + NETWORK_PAGE_SIZE, networkLogsTotal);
      const prevDisabled = networkLogsOffset <= 0;
      const nextDisabled = networkLogsOffset + NETWORK_PAGE_SIZE >= networkLogsTotal;
      el.innerHTML = `<span>Wyniki ${from}–${to} z ${networkLogsTotal}</span>
        <button type="button" id="net-btn-prev" ${prevDisabled ? 'disabled' : ''}>← Poprzednia</button>
        <button type="button" id="net-btn-next" ${nextDisabled ? 'disabled' : ''}>Następna →</button>`;
      document.getElementById('net-btn-prev')?.addEventListener('click', () => {
        networkLogsOffset = Math.max(0, networkLogsOffset - NETWORK_PAGE_SIZE);
        fetchNetworkLogs();
      });
      document.getElementById('net-btn-next')?.addEventListener('click', () => {
        networkLogsOffset += NETWORK_PAGE_SIZE;
        fetchNetworkLogs();
      });
    }

    async function fetchNetworkLogs() {
      const tbody = document.getElementById('net-table-body');
      const timeEl = document.getElementById('net-filter-time');
      const lastHours = timeEl ? (parseFloat(timeEl.value) || 24) : 24;
      if (tbody) tbody.innerHTML = '<tr><td colspan="11" class="loading-state">Ładowanie logów sieciowych…</td></tr>';
      try {
        const params = new URLSearchParams();
        params.set('network_only', '1');
        params.set('limit', String(NETWORK_PAGE_SIZE));
        params.set('offset', String(networkLogsOffset));
        params.set('last_hours', String(lastHours));
        const res = await fetch('/api/logs?' + params.toString());
        const data = await res.json();
        networkLogs = data.logs || [];
        networkLogsTotal = data.total ?? 0;
        networkCountEl.textContent = networkLogsTotal;
        await fetchNetworkAnalytics();
        applyNetworkFilters();
        updatePaginationNetwork();
      } catch (e) {
        if (tbody) tbody.innerHTML = '<tr><td colspan="11" class="empty-state">Błąd ładowania. Sprawdź połączenie.</td></tr>';
        document.getElementById('pagination-network').style.display = 'none';
      }
    }

    function toggleExpand(btn) {
      const entry = btn.closest('.log-entry');
      entry.classList.toggle('expanded');
      btn.textContent = entry.classList.contains('expanded') ? 'Pokaż mniej' : 'Pokaż więcej';
    }

    function logMatchesCurrentFilter(log) {
      const cat = (log._category || {}).display_name;
      const sev = (log._category || {}).severity;
      const a = log.agent;
      const agentStr = typeof a === 'object' ? (a && (a.name || a.id || '')) : (a || '');
      const fullLog = (log.full_log || '') + '';
      const catVal = (filterCategory && filterCategory.value) || '';
      const sevVal = (filterSeverity && filterSeverity.value) || '';
      const agentVal = (filterAgent && filterAgent.value) ? filterAgent.value.trim() : '';
      const qVal = (filterSearch && filterSearch.value) ? filterSearch.value.trim() : '';
      const lastHours = (filterTime && filterTime.value) ? parseFloat(filterTime.value) : 0;
      if (catVal && cat !== catVal) return false;
      if (sevVal && sev !== sevVal) return false;
      if (agentVal && !String(agentStr).includes(agentVal)) return false;
      if (qVal && !fullLog.toLowerCase().includes(qVal.toLowerCase())) return false;
      if (lastHours > 0) {
        const ts = log.timestamp || log['@timestamp'] || (log.data && log.data.timestamp);
        if (!ts) return false;
        const logTime = new Date(ts).getTime();
        const now = Date.now();
        if (isNaN(logTime) || now - logTime > lastHours * 3600 * 1000) return false;
      }
      return true;
    }

    function prependLogToView(log) {
      const sectionAll = document.getElementById('section-all');
      if (!sectionAll || !sectionAll.classList.contains('active') || !logsEl) return;
      const groupSame = (document.getElementById('group-same') || {}).checked;
      const cat = log._category || {};
      const agent = log.agent || {};
      const agentName = typeof agent === 'object' ? (agent.name || agent.id || '-') : '-';
      const fullLog = (log.full_log || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const sevClass = 'severity-' + (cat.severity || 'info');
      const html = `
        <div class="log-entry log-group" data-id="${log.id || ''}">
          <div class="meta">
            <span class="category-badge" style="background: ${cat.color}22; color: ${cat.color}">${cat.icon || ''} ${cat.display_name || 'Inne'}</span>
            <span class="${sevClass}">${cat.severity || 'info'}</span>
            <span>🕐 ${log.timestamp || '-'}</span>
            <span>🤖 ${agentName}</span>
            ${log.rule && log.rule.description ? '<span>📋 ' + (log.rule.description + '').replace(/</g, '&lt;') + '</span>' : ''}
          </div>
          <div class="full-log">${fullLog}</div>
          <button class="expand-btn" onclick="toggleExpand(this)">Pokaż więcej</button>
        </div>`;
      const first = logsEl.firstElementChild;
      if (first && first.classList && (first.classList.contains('empty-state') || first.classList.contains('loading-state'))) {
        first.remove();
      }
      logsEl.insertAdjacentHTML('afterbegin', html);
      logsTotal += 1;
      updatePaginationAll();
    }

    function applyFilters() {
      logsOffset = 0;
      fetchLogs();
    }

    function updatePaginationAll() {
      const el = document.getElementById('pagination-all');
      if (!el) return;
      if (logsTotal <= 0) { el.style.display = 'none'; return; }
      el.style.display = 'flex';
      const from = logsOffset + 1;
      const to = Math.min(logsOffset + LOGS_PAGE_SIZE, logsTotal);
      const prevDisabled = logsOffset <= 0;
      const nextDisabled = logsOffset + LOGS_PAGE_SIZE >= logsTotal;
      el.innerHTML = `<span>Wyniki ${from}–${to} z ${logsTotal}</span>
        <button type="button" id="btn-prev-page" ${prevDisabled ? 'disabled' : ''}>← Poprzednia</button>
        <button type="button" id="btn-next-page" ${nextDisabled ? 'disabled' : ''}>Następna →</button>`;
      document.getElementById('btn-prev-page')?.addEventListener('click', () => {
        logsOffset = Math.max(0, logsOffset - LOGS_PAGE_SIZE);
        fetchLogs();
      });
      document.getElementById('btn-next-page')?.addEventListener('click', () => {
        logsOffset += LOGS_PAGE_SIZE;
        fetchLogs();
      });
    }

    function setLastUpdated() {
      const el = document.getElementById('stat-updated');
      if (el) el.textContent = 'Aktualizacja: ' + new Date().toLocaleTimeString('pl-PL');
    }

    async function fetchLogs() {
      if (logsEl) logsEl.innerHTML = '<div class="loading-state">Ładowanie logów…</div>';
      const params = new URLSearchParams();
      params.set('limit', String(LOGS_PAGE_SIZE));
      params.set('offset', String(logsOffset));
      const cat = filterCategory.value;
      const sev = filterSeverity.value;
      const agent = filterAgent.value.trim();
      const q = (filterSearch && filterSearch.value) ? filterSearch.value.trim() : '';
      const lastHours = (filterTime && filterTime.value) ? parseFloat(filterTime.value) : '';
      if (cat) params.set('category', cat);
      if (sev) params.set('severity', sev);
      if (agent) params.set('agent', agent);
      if (q) params.set('q', q);
      if (lastHours) params.set('last_hours', lastHours);
      try {
        const res = await fetch('/api/logs?' + params.toString());
        const data = await res.json();
        allLogs = data.logs || [];
        logsTotal = data.total ?? 0;
        const groupSame = (document.getElementById('group-same') || {}).checked;
        renderLogs(allLogs, logsEl, groupSame);
        updatePaginationAll();
      } catch (e) {
        allLogs = [];
        logsTotal = 0;
        if (logsEl) logsEl.innerHTML = '<div class="empty-state">Błąd ładowania logów. Sprawdź połączenie.</div>';
        document.getElementById('pagination-all').style.display = 'none';
      }
    }

    async function fetchAlerts() {
      try {
        const res = await fetch('/api/alerts');
        const data = await res.json();
        const total = (data.critical || 0) + (data.high || 0);
        const wrap = document.getElementById('stat-alerts-wrap');
        const el = document.getElementById('stat-alerts');
        if (el) el.textContent = total;
        if (wrap) {
          wrap.style.display = total > 0 ? '' : 'none';
          wrap.style.color = (data.critical || 0) > 0 ? 'var(--danger)' : 'var(--warning)';
        }
      } catch (e) {}
    }
    async function refreshLogs() {
      const btn = document.getElementById('btn-refresh');
      if (btn) { btn.disabled = true; btn.textContent = '…'; }
      try {
        await fetch('/api/refresh', { method: 'POST' });
        await fetchLogs();
        await fetchStats();
        if (document.querySelector('.tab.active').dataset.tab === 'network') await fetchNetworkLogs();
      } catch (e) {}
      if (btn) { btn.disabled = false; btn.textContent = '🔄 Odśwież'; }
    }
    function exportAllLogs(format) {
      const params = new URLSearchParams();
      params.set('format', format || 'json');
      params.set('limit', '5000');
      const cat = filterCategory.value, sev = filterSeverity.value, agent = filterAgent.value.trim();
      const q = (filterSearch && filterSearch.value) ? filterSearch.value.trim() : '';
      const lastHours = (filterTime && filterTime.value) ? parseFloat(filterTime.value) : '';
      if (cat) params.set('category', cat);
      if (sev) params.set('severity', sev);
      if (agent) params.set('agent', agent);
      if (q) params.set('q', q);
      if (lastHours) params.set('last_hours', lastHours);
      window.open('/api/export?' + params.toString(), '_blank');
    }
    document.getElementById('btn-refresh')?.addEventListener('click', refreshLogs);
    document.getElementById('telemetry-apply-range')?.addEventListener('click', fetchTelemetry);
    document.getElementById('net-filter-time')?.addEventListener('change', () => {
      networkLogsOffset = 0;
      if (document.querySelector('.tab.active')?.dataset.tab === 'network') fetchNetworkLogs();
    });
    document.getElementById('btn-export-json')?.addEventListener('click', () => exportAllLogs('json'));
    document.getElementById('btn-export-csv')?.addEventListener('click', () => exportAllLogs('csv'));
    document.addEventListener('keydown', function(e) {
      if (e.key === '/' && !/^(input|textarea|select)$/i.test((e.target || {}).tagName)) {
        e.preventDefault();
        if (filterSearch) filterSearch.focus();
      }
      if (e.key === 'Escape') {
        const modal = document.getElementById('net-log-detail-modal');
        if (modal && modal.style.display === 'flex') modal.style.display = 'none';
      }
    });

    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        statTotal.textContent = data.total || 0;
        statNetwork.textContent = data.network_count ?? 0;
        statAgents.textContent = (data.agents || []).length;
        setLastUpdated();
        fetchAlerts();
        const cats = Object.keys(data.by_category || {}).sort();
      const currentVal = filterCategory.value;
      const optVals = [...filterCategory.querySelectorAll('option')].map(o => o.value).filter(Boolean);
      const catsSet = new Set(cats);
      const optSet = new Set(optVals);
      if (cats.length !== optSet.size || cats.some(c => !optSet.has(c))) {
        filterCategory.innerHTML = '<option value="">Wszystkie kategorie</option>' +
          cats.map(c => `<option value="${c}">${c}</option>`).join('');
        filterCategory.value = catsSet.has(currentVal) ? currentVal : '';
      }
        const topRules = data.top_rules || [];
        const tbody = document.getElementById('top-rules-body');
        if (tbody) {
          tbody.innerHTML = topRules.length ? topRules.map(r =>
            `<tr><td title="${(r.description || '').replace(/"/g, '&quot;')}">${(r.rule_id || '').replace(/</g, '&lt;')}</td><td>${r.count ?? 0}</td></tr>`
          ).join('') : '<tr><td colspan="2">Brak danych</td></tr>';
        }
      } catch (e) {
        if (statTotal) statTotal.textContent = '—';
        if (statNetwork) statNetwork.textContent = '—';
        if (statAgents) statAgents.textContent = '—';
      }
    }

    async function fetchServiceState() {
      const loadingEl = document.getElementById('service-loading');
      const contentEl = document.getElementById('service-content');
      const gridEl = document.getElementById('service-health-grid');
      if (loadingEl) loadingEl.style.display = 'flex';
      if (contentEl) contentEl.style.display = 'none';
      try {
        const res = await fetch('/api/health');
        const h = await res.json();
        if (loadingEl) loadingEl.style.display = 'none';
        if (contentEl) contentEl.style.display = 'block';
        if (!gridEl) return;
        const fmt = (v) => v == null ? '—' : v;
        const fmtNum = (v) => v == null ? '—' : (typeof v === 'number' ? v.toLocaleString() : v);
        const sizeStr = h.archive_size_bytes != null ? (h.archive_size_bytes >= 1048576 ? (h.archive_size_bytes/1048576).toFixed(1) + ' MB' : h.archive_size_bytes >= 1024 ? (h.archive_size_bytes/1024).toFixed(1) + ' KB' : h.archive_size_bytes) : '—';
        gridEl.innerHTML = [
          { label: 'Status', value: h.status || 'ok', cls: 'ok' },
          { label: 'Wersja', value: fmt(h.version) },
          { label: 'Wpisy w pamięci', value: fmtNum(h.logs_loaded) },
          { label: 'Wpisy w bazie', value: fmtNum(h.db_total) },
          { label: 'Plik archiwum istnieje', value: h.archive_exists ? 'Tak' : 'Nie', cls: h.archive_exists ? 'ok' : 'err' },
          { label: 'Rozmiar archiwum', value: sizeStr },
          { label: 'Ostatni odczyt', value: fmt(h.last_read_iso) },
          { label: 'Błędy odczytu (łącznie)', value: fmtNum(h.read_errors_total), cls: (h.read_errors_total || 0) > 0 ? 'warn' : 'ok' },
        ].map(c => `<div class="service-card"><h3>${c.label}</h3><div class="value ${c.cls || ''}">${typeof c.value === 'string' ? c.value.replace(/</g, '&lt;') : c.value}</div></div>`).join('');
      } catch (e) {
        if (loadingEl) loadingEl.style.display = 'none';
        if (contentEl) { contentEl.style.display = 'block'; contentEl.innerHTML = '<p style="color: var(--danger);">Błąd ładowania stanu serwisu.</p>'; }
      }
    }
    document.body.addEventListener('click', function(e) {
      if (e.target && e.target.id === 'service-refresh-btn') fetchServiceState();
    });

    function connectSSE() {
      const evtSource = new EventSource('/api/stream');
      evtSource.addEventListener('log', (e) => {
        try {
          const log = JSON.parse(e.data);
          allLogs.unshift(log);
          if (allLogs.length > 5000) allLogs.pop();
          if (isNetworkLog(log)) {
            networkLogs.unshift(log);
            if (networkLogs.length > 500) networkLogs.pop();
            networkCountEl.textContent = networkLogs.length;
            if (document.querySelector('.tab.active').dataset.tab === 'network') {
              applyNetworkFilters();
            }
          }
          if (logMatchesCurrentFilter(log)) prependLogToView(log);
          fetchStats();
        } catch (err) {}
      });
      evtSource.onerror = () => { evtSource.close(); setTimeout(connectSSE, 3000); };
    }

    fetchLogs().then(() => { fetchStats(); fetchNetworkLogs(); });
    connectSSE();
    setInterval(fetchStats, 10000);
    setInterval(fetchAlerts, 60000);
    fetch('/api/config').then(r => r.json()).then(c => {
      const btn = document.getElementById('btn-refresh');
      if (btn && c && c.refresh_enabled === false) btn.style.display = 'none';
    }).catch(() => {});
  </script>
</body>
</html>"""

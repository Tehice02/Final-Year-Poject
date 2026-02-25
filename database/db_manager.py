"""
SQLite persistence for alerts and traffic statistics.
"""

from __future__ import annotations

import csv
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from utils.logger import log_database, log_error


class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        log_database(f"Using database at {self.db_path}")

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            # Ensure schema exists for every connection (handles deleted DB files)
            self._ensure_schema(conn)
            yield conn
            conn.commit()
        except sqlite3.DatabaseError as exc:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize_database(self) -> None:
        try:
            with self._connect() as conn:
                self._ensure_schema(conn)

            log_database("Database schema is ready.")
        except sqlite3.DatabaseError as exc:
            if "malformed" in str(exc).lower():
                log_error("Database file is malformed; creating a fresh database with backup.", component="Database")
                self._reset_corrupted_db()
                with self._connect() as conn:
                    self._ensure_schema(conn)
                log_database("Database recreated after corruption.")
                return
            log_error(f"Database init failed: {exc}", component="Database", exc_info=True)
            raise
        except Exception as exc:
            log_error(f"Database init failed: {exc}", component="Database", exc_info=True)
            raise

    def _ensure_alert_columns(self, conn: sqlite3.Connection) -> None:
        """Add missing columns for existing databases created with old schemas."""
        required_cols = {
            "created_at": "TEXT DEFAULT CURRENT_TIMESTAMP",
            "src_ip": "TEXT",
            "dst_ip": "TEXT",
            "src_port": "INTEGER",
            "dst_port": "INTEGER",
            "protocol": "TEXT",
            "attack_type": "TEXT",
            "class_3": "INTEGER",
            "confidence": "REAL",
            "severity": "TEXT",
            "in_bytes": "INTEGER",
            "out_bytes": "INTEGER",
            "in_pkts": "INTEGER",
            "out_pkts": "INTEGER",
            "flow_duration_ms": "INTEGER",
        }

        cur = conn.cursor()
        cur.execute("PRAGMA table_info(alerts)")
        existing = {row[1] for row in cur.fetchall()}

        for col, definition in required_cols.items():
            if col not in existing:
                cur.execute(f"ALTER TABLE alerts ADD COLUMN {col} {definition}")

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Create tables and indexes if missing."""
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                attack_type TEXT NOT NULL,
                class_3 INTEGER NOT NULL,
                confidence REAL NOT NULL,
                severity TEXT NOT NULL,
                in_bytes INTEGER,
                out_bytes INTEGER,
                in_pkts INTEGER,
                out_pkts INTEGER,
                flow_duration_ms INTEGER
            )
            """
        )
        self._ensure_alert_columns(conn)

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_daily (
                date TEXT PRIMARY KEY,
                packets INTEGER DEFAULT 0,
                flows INTEGER DEFAULT 0,
                alerts INTEGER DEFAULT 0,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type)")

    def _reset_corrupted_db(self) -> None:
        """Backup and recreate a corrupted database file."""
        try:
            if self.db_path.exists():
                ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
                backup_path = self.db_path.with_suffix(f".bak.{ts}")
                self.db_path.rename(backup_path)
                log_database(f"Corrupted database backed up to {backup_path}")
        except Exception as exc:
            log_error(f"Failed to backup corrupted DB: {exc}", component="Database", exc_info=True)

    def insert_alert(self, alert: Dict) -> Optional[int]:
        if not alert.get("is_attack", False):
            return None

        try:
            try:
                ts = alert.get("timestamp", time.time())
                created_at = datetime.fromtimestamp(ts).isoformat()
            except Exception:
                created_at = datetime.utcnow().isoformat()

            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO alerts (
                        created_at, src_ip, dst_ip, src_port, dst_port, protocol,
                        attack_type, class_3, confidence, severity,
                        in_bytes, out_bytes, in_pkts, out_pkts, flow_duration_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        created_at,
                        alert.get("src_ip"),
                        alert.get("dst_ip"),
                        alert.get("src_port"),
                        alert.get("dst_port"),
                        alert.get("protocol"),
                        alert.get("attack_type"),
                        int(alert.get("class_3", 0)),
                        float(alert.get("confidence_score", 0.0)),
                        alert.get("severity", "SAFE"),
                        int(alert.get("in_bytes", 0)),
                        int(alert.get("out_bytes", 0)),
                        int(alert.get("in_pkts", 0)),
                        int(alert.get("out_pkts", 0)),
                        int(alert.get("flow_duration_ms", 0)),
                    ),
                )
                return cur.lastrowid
        except Exception as exc:
            log_error(f"Failed to insert alert: {exc}", component="Database", exc_info=True)
            return None

    def get_recent_alerts(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT * FROM alerts
                    ORDER BY datetime(created_at) DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
                rows = cur.fetchall()
                return [dict(row) for row in rows]
        except Exception as exc:
            log_error(f"Failed to fetch alerts: {exc}", component="Database", exc_info=True)
            return []

    def get_alerts_by_filter(self, filters: Dict) -> List[Dict]:
        clauses = []
        params: List = []

        if src_ip := filters.get("src_ip"):
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip := filters.get("dst_ip"):
            clauses.append("dst_ip = ?")
            params.append(dst_ip)
        if attack := filters.get("attack_type"):
            clauses.append("attack_type = ?")
            params.append(attack)
        if severity := filters.get("severity"):
            clauses.append("severity = ?")
            params.append(severity)
        if start := filters.get("start"):
            clauses.append("datetime(created_at) >= datetime(?)")
            params.append(start)
        if end := filters.get("end"):
            clauses.append("datetime(created_at) <= datetime(?)")
            params.append(end)

        where_clause = " AND ".join(clauses) if clauses else "1=1"
        query = f"SELECT * FROM alerts WHERE {where_clause} ORDER BY datetime(created_at) DESC LIMIT 500"

        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(query, params)
                return [dict(row) for row in cur.fetchall()]
        except Exception as exc:
            log_error(f"Failed to filter alerts: {exc}", component="Database", exc_info=True)
            return []

    def get_attack_distribution(self, days: int = 1) -> Dict[str, int]:
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT attack_type, COUNT(*) AS cnt
                    FROM alerts
                    WHERE datetime(created_at) >= datetime('now', ?)
                    GROUP BY attack_type
                    """,
                    (f"-{days} days",),
                )
                return {row["attack_type"]: row["cnt"] for row in cur.fetchall()}
        except Exception as exc:
            log_error(f"Failed to compute distribution: {exc}", component="Database", exc_info=True)
            return {}

    def get_statistics(self, days: int = 7) -> Dict[str, List[Dict]]:
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT * FROM traffic_daily
                    WHERE date >= date('now', ?)
                    ORDER BY date ASC
                    """,
                    (f"-{days} days",),
                )
                traffic = [dict(row) for row in cur.fetchall()]

                cur.execute(
                    """
                    SELECT date(created_at) as day, COUNT(*) as alerts
                    FROM alerts
                    WHERE date(created_at) >= date('now', ?)
                    GROUP BY day
                    ORDER BY day ASC
                    """,
                    (f"-{days} days",),
                )
                alerts_by_day = [dict(row) for row in cur.fetchall()]

            return {"traffic": traffic, "alerts": alerts_by_day}
        except Exception as exc:
            log_error(f"Failed to read statistics: {exc}", component="Database", exc_info=True)
            return {"traffic": [], "alerts": []}

    def record_traffic(self, packets: int, flows: int, alerts: int) -> None:
        today = datetime.utcnow().date().isoformat()
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO traffic_daily (date, packets, flows, alerts, updated_at)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(date) DO UPDATE SET
                        packets = excluded.packets,
                        flows = excluded.flows,
                        alerts = excluded.alerts,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (today, int(packets), int(flows), int(alerts)),
                )
        except Exception as exc:
            log_error(f"Failed to record traffic: {exc}", component="Database", exc_info=True)

    def get_today_counts(self) -> Dict[str, int]:
        today = datetime.utcnow().date().isoformat()
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT packets, flows, alerts FROM traffic_daily WHERE date = ?", (today,)
                )
                row = cur.fetchone()
                if not row:
                    return {"packets": 0, "flows": 0, "alerts": 0}
                return {"packets": row["packets"], "flows": row["flows"], "alerts": row["alerts"]}
        except Exception as exc:
            log_error(f"Failed to read today's counts: {exc}", component="Database", exc_info=True)
            return {"packets": 0, "flows": 0, "alerts": 0}

    def get_alert_count_today(self) -> int:
        today = datetime.utcnow().date().isoformat()
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM alerts WHERE date(created_at) = ?", (today,))
                row = cur.fetchone()
                return row[0] if row else 0
        except Exception as exc:
            log_error(f"Failed to count today's alerts: {exc}", component="Database", exc_info=True)
            return 0

    def get_average_confidence(self) -> float:
        """Return average confidence across all alerts (0 if none)."""
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute("SELECT AVG(confidence) FROM alerts WHERE confidence IS NOT NULL")
                row = cur.fetchone()
                return round(row[0], 2) if row and row[0] is not None else 0.0
        except Exception as exc:
            log_error(f"Failed to compute average confidence: {exc}", component="Database", exc_info=True)
            return 0.0

    def export_alerts_csv(self, output_path: Path) -> Optional[Path]:
        try:
            with self._connect() as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM alerts ORDER BY datetime(created_at) DESC")
                rows = cur.fetchall()
                if not rows:
                    return None

                output_path.parent.mkdir(parents=True, exist_ok=True)
                with output_path.open("w", newline="") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys())
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(dict(row))

            return output_path
        except Exception as exc:
            log_error(f"Failed to export CSV: {exc}", component="Database", exc_info=True)
            return None

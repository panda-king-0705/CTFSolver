"""Global memory: four stores in one sqlite database, searchable with FTS5
(falling back to LIKE if a build lacks it).

- procedural : the technique library -- solve skeletons that compound across events
- episodic   : one row per attempt
- conceptual : durable facts (flag formats, archetypes, CVEs)
- working    : the per-challenge blackboard (cleared/hidden when a challenge is cancelled)
"""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Optional

from ..models import Attempt, Category, Technique


def _fts5_available(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("CREATE VIRTUAL TABLE _fts_probe USING fts5(x)")
        conn.execute("DROP TABLE _fts_probe")
        return True
    except sqlite3.OperationalError:
        return False


class MemoryStore:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL" if db_path != ":memory:" else "PRAGMA synchronous=OFF")
        self.fts = _fts5_available(self.conn)
        self._init_schema()

    # ------------------------------------------------------------------ #
    def _init_schema(self) -> None:
        c = self.conn
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS techniques(
                id TEXT PRIMARY KEY, title TEXT, category TEXT,
                pattern TEXT, recipe TEXT, tags TEXT, uses INT DEFAULT 0,
                wins INT DEFAULT 0, source TEXT);
            CREATE TABLE IF NOT EXISTS episodes(
                id TEXT PRIMARY KEY, challenge_id TEXT, specialist TEXT,
                status TEXT, flag TEXT, notes TEXT, started_at REAL, ended_at REAL,
                blob TEXT);
            CREATE TABLE IF NOT EXISTS concepts(
                id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT,
                tags TEXT, ts REAL);
            CREATE TABLE IF NOT EXISTS working(
                challenge_id TEXT, key TEXT, value TEXT, ts REAL,
                PRIMARY KEY(challenge_id, key));
            CREATE INDEX IF NOT EXISTS ix_tech_cat ON techniques(category);
            CREATE INDEX IF NOT EXISTS ix_ep_chal ON episodes(challenge_id);
            """
        )
        if self.fts:
            c.executescript(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS techniques_fts USING fts5(id UNINDEXED, body);
                CREATE VIRTUAL TABLE IF NOT EXISTS concepts_fts USING fts5(ref UNINDEXED, body);
                """
            )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    # Procedural: the technique library
    # ------------------------------------------------------------------ #
    def add_technique(self, t: Technique) -> str:
        self.conn.execute(
            "INSERT OR REPLACE INTO techniques VALUES(?,?,?,?,?,?,?,?,?)",
            (t.id, t.title, t.category.value, t.pattern, t.recipe,
             json.dumps(t.tags), t.uses, t.wins, t.source),
        )
        if self.fts:
            body = " ".join([t.title, t.pattern, t.recipe, " ".join(t.tags), t.category.value])
            self.conn.execute("DELETE FROM techniques_fts WHERE id=?", (t.id,))
            self.conn.execute("INSERT INTO techniques_fts(id, body) VALUES(?,?)", (t.id, body))
        self.conn.commit()
        return t.id

    def _row_to_technique(self, r: sqlite3.Row) -> Technique:
        return Technique(
            id=r["id"], title=r["title"], category=Category.coerce(r["category"]),
            pattern=r["pattern"], recipe=r["recipe"], tags=json.loads(r["tags"] or "[]"),
            uses=r["uses"], wins=r["wins"], source=r["source"],
        )

    def recall_techniques(
        self, query: str, category: Optional[Category] = None, limit: int = 5
    ) -> list[Technique]:
        """Procedural recall used by triage: pull solve skeletons that match."""
        ids: list[str] = []
        q = (query or "").strip()
        if self.fts and q:
            fts_q = " OR ".join(_tokens(q))
            if fts_q:
                try:
                    rows = self.conn.execute(
                        "SELECT id FROM techniques_fts WHERE techniques_fts MATCH ? LIMIT ?",
                        (fts_q, limit * 4),
                    ).fetchall()
                    ids = [r["id"] for r in rows]
                except sqlite3.OperationalError:
                    ids = []
        results: list[Technique] = []
        if ids:
            placeholders = ",".join("?" * len(ids))
            rows = self.conn.execute(
                f"SELECT * FROM techniques WHERE id IN ({placeholders})", ids
            ).fetchall()
            results = [self._row_to_technique(r) for r in rows]
        else:
            # LIKE fallback (or empty query): rank by category match + usage
            like = f"%{q}%"
            rows = self.conn.execute(
                "SELECT * FROM techniques WHERE (title LIKE ? OR pattern LIKE ? OR recipe LIKE ? OR tags LIKE ?)",
                (like, like, like, like),
            ).fetchall() if q else self.conn.execute("SELECT * FROM techniques").fetchall()
            results = [self._row_to_technique(r) for r in rows]
        if category is not None:
            results = [t for t in results if t.category == category] or results
        results.sort(key=lambda t: (t.category == category, t.win_rate, t.uses), reverse=True)
        return results[:limit]

    def bump_technique(self, technique_id: str, win: bool) -> None:
        self.conn.execute(
            "UPDATE techniques SET uses=uses+1, wins=wins+? WHERE id=?",
            (1 if win else 0, technique_id),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    # Episodic
    # ------------------------------------------------------------------ #
    def add_episode(self, attempt: Attempt) -> str:
        o = attempt.outcome
        self.conn.execute(
            "INSERT OR REPLACE INTO episodes VALUES(?,?,?,?,?,?,?,?,?)",
            (
                attempt.id, attempt.challenge_id, attempt.specialist,
                o.status.value, (o.flag.value if o.flag else None), o.notes,
                attempt.started_at, attempt.ended_at,
                json.dumps({"steps": o.steps, "cost_usd": o.cost_usd, "tool_calls": o.tool_calls}),
            ),
        )
        self.conn.commit()
        return attempt.id

    def episodes_for(self, challenge_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM episodes WHERE challenge_id=? ORDER BY started_at", (challenge_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def recent_episodes(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM episodes ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Conceptual
    # ------------------------------------------------------------------ #
    def add_concept(self, key: str, value: str, tags: Optional[list[str]] = None) -> None:
        cur = self.conn.execute(
            "INSERT INTO concepts(key, value, tags, ts) VALUES(?,?,?,?)",
            (key, value, json.dumps(tags or []), time.time()),
        )
        if self.fts:
            ref = cur.lastrowid
            self.conn.execute(
                "INSERT INTO concepts_fts(ref, body) VALUES(?,?)",
                (ref, f"{key} {value} {' '.join(tags or [])}"),
            )
        self.conn.commit()

    def recall_concepts(self, query: str, limit: int = 5) -> list[dict]:
        q = (query or "").strip()
        if self.fts and q:
            toks = " OR ".join(_tokens(q))
            if toks:
                try:
                    refs = [r["ref"] for r in self.conn.execute(
                        "SELECT ref FROM concepts_fts WHERE concepts_fts MATCH ? LIMIT ?",
                        (toks, limit),
                    ).fetchall()]
                    if refs:
                        ph = ",".join("?" * len(refs))
                        rows = self.conn.execute(
                            f"SELECT * FROM concepts WHERE id IN ({ph})", refs
                        ).fetchall()
                        return [dict(r) for r in rows]
                except sqlite3.OperationalError:
                    pass
        like = f"%{q}%"
        rows = self.conn.execute(
            "SELECT * FROM concepts WHERE key LIKE ? OR value LIKE ? LIMIT ?",
            (like, like, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ #
    # Working blackboard (per challenge)
    # ------------------------------------------------------------------ #
    def working_set(self, challenge_id: str, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO working VALUES(?,?,?,?)",
            (challenge_id, key, value, time.time()),
        )
        self.conn.commit()

    def working_get(self, challenge_id: str, key: str) -> Optional[str]:
        r = self.conn.execute(
            "SELECT value FROM working WHERE challenge_id=? AND key=?", (challenge_id, key)
        ).fetchone()
        return r["value"] if r else None

    def working_all(self, challenge_id: str) -> dict[str, str]:
        rows = self.conn.execute(
            "SELECT key, value FROM working WHERE challenge_id=?", (challenge_id,)
        ).fetchall()
        return {r["key"]: r["value"] for r in rows}

    def working_clear(self, challenge_id: str) -> None:
        """Hide a cancelled challenge's notes from the shared blackboard."""
        self.conn.execute("DELETE FROM working WHERE challenge_id=?", (challenge_id,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def _tokens(q: str) -> list[str]:
    """Alphanumeric tokens for an FTS OR-query, quoted to avoid syntax errors."""
    import re

    return [f'"{t}"' for t in re.findall(r"[A-Za-z0-9_]+", q)]

"""A local sample corpus (SQLite) with fuzzy-hash similarity clustering.

Every scan can be persisted so an analyst builds up a searchable history and can
ask "what have I seen that looks like this?" — the kind of lightweight sample
management a triage workflow needs without standing up a full malware zoo.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .core.hashing import fuzzy_compare
from .core.model import AnalysisReport

DEFAULT_DB = os.path.expanduser("~/.strix/corpus.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    sha256     TEXT PRIMARY KEY,
    md5        TEXT,
    sha1       TEXT,
    imphash    TEXT,
    fuzzy      TEXT,
    path       TEXT,
    size       INTEGER,
    file_type  TEXT,
    format     TEXT,
    verdict    TEXT,
    score      INTEGER,
    entropy    REAL,
    attack     TEXT,
    findings   INTEGER,
    first_seen REAL,
    last_seen  REAL
);
CREATE INDEX IF NOT EXISTS idx_verdict ON samples(verdict);
CREATE INDEX IF NOT EXISTS idx_imphash ON samples(imphash);
"""


@dataclass
class Sample:
    sha256: str
    md5: str
    imphash: str
    fuzzy: str
    path: str
    size: int
    file_type: str
    format: str
    verdict: str
    score: int
    attack: list
    findings: int
    first_seen: float
    last_seen: float


class Corpus:
    def __init__(self, db_path: str = DEFAULT_DB):
        self.path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        # check_same_thread=False so the threaded web server can share one
        # connection; a lock serialises writes.
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self.db.executescript(_SCHEMA)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- writes -------------------------------------------------------------
    def add(self, report: AnalysisReport) -> bool:
        f = report.file
        now = time.time()
        sha = f.hashes.get("sha256", "")
        if not sha:
            return False
        with self._lock:
            existing = self.db.execute("SELECT first_seen FROM samples WHERE sha256=?", (sha,)).fetchone()
            first = existing["first_seen"] if existing else now
            self.db.execute(
            """INSERT INTO samples
               (sha256,md5,sha1,imphash,fuzzy,path,size,file_type,format,verdict,score,entropy,attack,findings,first_seen,last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(sha256) DO UPDATE SET
                 path=excluded.path, verdict=excluded.verdict, score=excluded.score,
                 attack=excluded.attack, findings=excluded.findings, last_seen=excluded.last_seen""",
            (sha, f.hashes.get("md5", ""), f.hashes.get("sha1", ""), f.hashes.get("imphash", ""),
             f.hashes.get("fuzzy", ""), f.path, f.size, f.file_type, f.format_family,
             report.verdict.value, report.score, f.entropy,
             json.dumps(report.attack_techniques), len(report.findings), first, now))
            self.db.commit()
        return True

    # -- reads --------------------------------------------------------------
    def all(self, limit: int = 1000) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM samples ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()

    def get(self, sha256: str) -> Optional[sqlite3.Row]:
        return self.db.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()

    def stats(self) -> dict:
        rows = self.db.execute(
            "SELECT verdict, COUNT(*) n FROM samples GROUP BY verdict").fetchall()
        total = self.db.execute("SELECT COUNT(*) n FROM samples").fetchone()["n"]
        return {"total": total, "by_verdict": {r["verdict"]: r["n"] for r in rows}}

    # -- similarity ---------------------------------------------------------
    def similar(self, sha256: str, threshold: int = 50) -> list[tuple[str, int]]:
        target = self.get(sha256)
        if not target or not target["fuzzy"]:
            return []
        out = []
        for row in self.all(100000):
            if row["sha256"] == sha256 or not row["fuzzy"]:
                continue
            sim = fuzzy_compare(target["fuzzy"], row["fuzzy"])
            if sim >= threshold:
                out.append((row["sha256"], sim))
        return sorted(out, key=lambda x: x[1], reverse=True)

    def cluster(self, threshold: int = 55) -> list[list[sqlite3.Row]]:
        """Single-linkage clustering on fuzzy-hash similarity (+ exact imphash)."""
        rows = [r for r in self.all(100000) if r["fuzzy"]]
        n = len(rows)
        parent = list(range(n))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        def union(a, b):
            parent[find(a)] = find(b)

        for i in range(n):
            for j in range(i + 1, n):
                same_imp = (rows[i]["imphash"] and rows[i]["imphash"] == rows[j]["imphash"])
                if same_imp or fuzzy_compare(rows[i]["fuzzy"], rows[j]["fuzzy"]) >= threshold:
                    union(i, j)
        groups: dict[int, list] = {}
        for i in range(n):
            groups.setdefault(find(i), []).append(rows[i])
        # only return clusters with more than one member, largest first
        clusters = [g for g in groups.values() if len(g) > 1]
        return sorted(clusters, key=len, reverse=True)

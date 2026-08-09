"""Persistent hybrid retrieval backed by SQLite FTS5 and dense vectors."""

from __future__ import annotations

import json
import math
import re
import sqlite3
import struct
from pathlib import Path
from typing import Iterable

from app.rag.embeddings import EmbeddingProvider
from app.rag.models import KnowledgeChunk, RetrievalHit


_SEARCH_TOKEN_RE = re.compile(
    r"CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?|[A-Za-z0-9_./:\\-]{2,}|[\u4e00-\u9fff]{2,}",
    re.IGNORECASE,
)
_EXACT_ID_RE = re.compile(r"\b(?:CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?)\b", re.I)


def _pack_vector(vector: list[float]) -> bytes:
    return struct.pack(f"<{len(vector)}f", *vector)


def _unpack_vector(value: bytes, dimension: int) -> list[float]:
    if not value or dimension <= 0:
        return []
    return list(struct.unpack(f"<{dimension}f", value))


def _cosine_normalized(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    # Providers normalize vectors. Clamp small numeric drift.
    return max(-1.0, min(1.0, sum(a * b for a, b in zip(left, right))))


class SQLiteKnowledgeStore:
    """Small/medium local corpus store with deterministic hybrid retrieval."""

    def __init__(self, path: str | Path, embedding: EmbeddingProvider):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.embedding = embedding
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS knowledge_documents (
                    knowledge_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source_uri TEXT NOT NULL DEFAULT '',
                    version TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    checksum TEXT NOT NULL,
                    embedding BLOB NOT NULL,
                    embedding_dimension INTEGER NOT NULL,
                    embedding_model TEXT NOT NULL
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                    knowledge_id UNINDEXED,
                    title,
                    content,
                    source UNINDEXED,
                    tokenize='unicode61'
                );
                CREATE TABLE IF NOT EXISTS rag_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )

    def upsert(self, chunks: Iterable[KnowledgeChunk]) -> int:
        prepared = [chunk.with_checksum() for chunk in chunks]
        if not prepared:
            return 0
        texts = [f"{chunk.title}\n{chunk.content}" for chunk in prepared]
        vectors = self.embedding.embed(texts)
        with self._connect() as conn:
            for chunk, vector in zip(prepared, vectors):
                old = conn.execute(
                    "SELECT checksum, embedding_model FROM knowledge_documents "
                    "WHERE knowledge_id = ?",
                    (chunk.knowledge_id,),
                ).fetchone()
                if (
                    old
                    and old["checksum"] == chunk.checksum
                    and old["embedding_model"] == self.embedding.name
                ):
                    continue
                conn.execute(
                    """
                    INSERT INTO knowledge_documents (
                        knowledge_id, source, title, content, source_uri, version,
                        metadata_json, checksum, embedding, embedding_dimension,
                        embedding_model
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(knowledge_id) DO UPDATE SET
                        source=excluded.source,
                        title=excluded.title,
                        content=excluded.content,
                        source_uri=excluded.source_uri,
                        version=excluded.version,
                        metadata_json=excluded.metadata_json,
                        checksum=excluded.checksum,
                        embedding=excluded.embedding,
                        embedding_dimension=excluded.embedding_dimension,
                        embedding_model=excluded.embedding_model
                    """,
                    (
                        chunk.knowledge_id,
                        chunk.source,
                        chunk.title,
                        chunk.content,
                        chunk.source_uri,
                        chunk.version,
                        json.dumps(chunk.metadata, ensure_ascii=False, sort_keys=True),
                        chunk.checksum,
                        _pack_vector(vector),
                        len(vector),
                        self.embedding.name,
                    ),
                )
                conn.execute(
                    "DELETE FROM knowledge_fts WHERE knowledge_id = ?",
                    (chunk.knowledge_id,),
                )
                conn.execute(
                    "INSERT INTO knowledge_fts(knowledge_id,title,content,source) "
                    "VALUES (?, ?, ?, ?)",
                    (chunk.knowledge_id, chunk.title, chunk.content, chunk.source),
                )
            conn.execute(
                "INSERT INTO rag_metadata(key,value) VALUES('embedding_model',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (self.embedding.name,),
            )
        return len(prepared)

    def count_by_source(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT source, COUNT(*) AS n FROM knowledge_documents GROUP BY source"
            ).fetchall()
        return {str(row["source"]): int(row["n"]) for row in rows}

    def prune_sources_except(
        self, sources: set[str], knowledge_ids: set[str]
    ) -> int:
        """Remove stale managed-corpus rows while preserving runtime caches."""
        if not sources:
            return 0
        placeholders = ",".join("?" for _ in sources)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT knowledge_id FROM knowledge_documents WHERE source IN ({placeholders})",
                sorted(sources),
            ).fetchall()
            stale = [
                str(row["knowledge_id"])
                for row in rows
                if str(row["knowledge_id"]) not in knowledge_ids
            ]
            conn.executemany(
                "DELETE FROM knowledge_fts WHERE knowledge_id = ?",
                ((knowledge_id,) for knowledge_id in stale),
            )
            conn.executemany(
                "DELETE FROM knowledge_documents WHERE knowledge_id = ?",
                ((knowledge_id,) for knowledge_id in stale),
            )
        return len(stale)

    def set_metadata(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO rag_metadata(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (key, value),
            )

    def get_metadata(self, key: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM rag_metadata WHERE key = ?",
                (key,),
            ).fetchone()
        return str(row["value"]) if row else None

    def get(self, knowledge_id: str) -> KnowledgeChunk | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM knowledge_documents WHERE knowledge_id = ?",
                (knowledge_id,),
            ).fetchone()
        return self._row_to_chunk(row) if row else None

    def _source_clause(self, sources: list[str] | None) -> tuple[str, list[str]]:
        if not sources:
            return "", []
        placeholders = ",".join("?" for _ in sources)
        return f" AND source IN ({placeholders})", list(sources)

    def _lexical_rows(
        self, query: str, sources: list[str] | None, limit: int
    ) -> list[sqlite3.Row]:
        tokens = list(dict.fromkeys(_SEARCH_TOKEN_RE.findall(query)))[:24]
        if not tokens:
            return []
        fts_query = " OR ".join(f'"{token.replace(chr(34), "")}"' for token in tokens)
        source_clause, params = self._source_clause(sources)
        with self._connect() as conn:
            try:
                return conn.execute(
                    "SELECT knowledge_id, bm25(knowledge_fts) AS rank "
                    "FROM knowledge_fts WHERE knowledge_fts MATCH ?"
                    f"{source_clause} ORDER BY rank LIMIT ?",
                    [fts_query, *params, limit],
                ).fetchall()
            except sqlite3.OperationalError:
                return []

    def _candidate_rows(self, sources: list[str] | None) -> list[sqlite3.Row]:
        source_clause, params = self._source_clause(sources)
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM knowledge_documents WHERE 1=1"
                f"{source_clause}",
                params,
            ).fetchall()

    def search(
        self,
        query: str,
        *,
        sources: list[str] | None = None,
        top_k: int = 5,
        candidate_k: int = 20,
    ) -> list[RetrievalHit]:
        query = query.strip()
        if not query or top_k < 1:
            return []

        lexical = self._lexical_rows(query, sources, candidate_k)
        lexical_rank = {
            str(row["knowledge_id"]): rank
            for rank, row in enumerate(lexical, start=1)
        }

        rows = self._candidate_rows(sources)
        query_vector = self.embedding.embed([query])[0]
        dense_scored: list[tuple[str, float]] = []
        rows_by_id = {str(row["knowledge_id"]): row for row in rows}
        for row in rows:
            vector = _unpack_vector(
                row["embedding"], int(row["embedding_dimension"])
            )
            similarity = _cosine_normalized(query_vector, vector)
            dense_scored.append((str(row["knowledge_id"]), similarity))
        dense_scored.sort(key=lambda item: item[1], reverse=True)
        dense_rank = {
            knowledge_id: rank
            for rank, (knowledge_id, _score) in enumerate(
                dense_scored[:candidate_k], start=1
            )
        }

        exact_terms = {match.upper() for match in _EXACT_ID_RE.findall(query)}
        candidate_ids = set(lexical_rank) | set(dense_rank)
        for knowledge_id, row in rows_by_id.items():
            haystack = f"{knowledge_id} {row['title']} {row['content']}".upper()
            if any(term in haystack for term in exact_terms):
                candidate_ids.add(knowledge_id)

        scored: list[tuple[str, float, bool]] = []
        for knowledge_id in candidate_ids:
            row = rows_by_id.get(knowledge_id)
            if not row:
                continue
            score = 0.0
            if knowledge_id in lexical_rank:
                score += 1.0 / (60 + lexical_rank[knowledge_id])
            if knowledge_id in dense_rank:
                score += 1.0 / (60 + dense_rank[knowledge_id])
            haystack = f"{knowledge_id} {row['title']} {row['content']}".upper()
            exact = bool(exact_terms and any(term in haystack for term in exact_terms))
            if exact:
                score += 0.05
            # Map the compact RRF range into a readable 0-1 score.
            normalized = min(1.0, score * 15.0)
            if math.isfinite(normalized):
                scored.append((knowledge_id, normalized, exact))
        scored.sort(key=lambda item: item[1], reverse=True)

        hits: list[RetrievalHit] = []
        for knowledge_id, score, exact in scored[:top_k]:
            row = rows_by_id[knowledge_id]
            hits.append(
                RetrievalHit(
                    knowledge_id=knowledge_id,
                    source=row["source"],
                    title=row["title"],
                    content=row["content"],
                    source_uri=row["source_uri"],
                    version=row["version"],
                    metadata=json.loads(row["metadata_json"]),
                    score=round(score, 4),
                    lexical_rank=lexical_rank.get(knowledge_id),
                    dense_rank=dense_rank.get(knowledge_id),
                    exact_match=exact,
                )
            )
        return hits

    @staticmethod
    def _row_to_chunk(row: sqlite3.Row) -> KnowledgeChunk:
        return KnowledgeChunk(
            knowledge_id=row["knowledge_id"],
            source=row["source"],
            title=row["title"],
            content=row["content"],
            source_uri=row["source_uri"],
            version=row["version"],
            metadata=json.loads(row["metadata_json"]),
            checksum=row["checksum"],
        )

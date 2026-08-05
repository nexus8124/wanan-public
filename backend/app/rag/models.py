"""Data models shared by ingestion, retrieval, the Agent, and the API."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, Field


KnowledgeSource = Literal["playbook", "sigma", "mitre_attack", "nvd"]


class KnowledgeChunk(BaseModel):
    knowledge_id: str
    source: KnowledgeSource
    title: str
    content: str
    source_uri: str = ""
    version: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    checksum: str = ""

    def with_checksum(self) -> "KnowledgeChunk":
        if self.checksum:
            return self
        payload = json.dumps(
            {
                "source": self.source,
                "title": self.title,
                "content": self.content,
                "source_uri": self.source_uri,
                "version": self.version,
                "metadata": self.metadata,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return self.model_copy(
            update={"checksum": hashlib.sha256(payload.encode("utf-8")).hexdigest()}
        )


class RetrievalHit(BaseModel):
    knowledge_id: str
    source: KnowledgeSource
    title: str
    content: str
    source_uri: str = ""
    version: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    score: float = Field(ge=0.0, le=1.0)
    lexical_rank: int | None = None
    dense_rank: int | None = None
    exact_match: bool = False


class RetrievalResult(BaseModel):
    query: str
    sources: list[str] = Field(default_factory=list)
    hits: list[RetrievalHit] = Field(default_factory=list)
    context: str = ""
    skipped_reason: str | None = None
    corpus_version: str = ""
    embedding_model: str = ""
    routing: dict[str, Any] = Field(default_factory=dict)

"""Read-only RAG observability and retrieval API."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query

from app.rag.service import get_rag_service


router = APIRouter(prefix="/api/rag", tags=["rag"])


@router.get("/status")
def rag_status() -> dict:
    """Return corpus counts, version, storage, and embedding configuration."""
    return get_rag_service().status()


@router.get("/search")
def rag_search(
    q: str = Query(min_length=2, max_length=6000),
    source: Literal["playbook", "sigma", "mitre_attack", "cisa_kev", "nvd"] | None = None,
    top_k: int = Query(default=4, ge=1, le=12),
) -> dict:
    """Inspect retrieval results without invoking an LLM or consuming tokens."""
    result = get_rag_service().search(
        q,
        sources=[source] if source else None,
        top_k=top_k,
    )
    return result.model_dump(mode="json")

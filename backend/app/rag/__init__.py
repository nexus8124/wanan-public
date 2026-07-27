"""Security knowledge retrieval for the alert-triage agent.

The RAG package deliberately separates general security knowledge (``KB-*``)
from case evidence (``EV-*``).  Knowledge explains how a technique, rule, or
playbook works; it must never be treated as proof that an event happened.
"""

from app.rag.service import RagService, get_rag_service

__all__ = ["RagService", "get_rag_service"]

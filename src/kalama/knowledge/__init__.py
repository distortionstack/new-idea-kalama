"""Deterministic, context-bound cross-run knowledge."""
from .models import KnowledgeRecord, TrustState
from .store import KnowledgeStore
from .retrieval import retrieve_compatible

__all__ = ["KnowledgeRecord", "TrustState", "KnowledgeStore", "retrieve_compatible"]

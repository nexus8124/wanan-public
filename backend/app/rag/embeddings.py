"""Local embedding providers.

The deterministic hashing provider is intentionally dependency-free and makes
CI/offline Windows installations reproducible.  A sentence-transformers
provider can be selected through configuration for semantic multilingual
retrieval (for example ``BAAI/bge-m3``).
"""

from __future__ import annotations

import hashlib
import math
import re
from functools import lru_cache
from typing import Protocol


class EmbeddingProvider(Protocol):
    name: str
    dimension: int

    def embed(self, texts: list[str]) -> list[list[float]]: ...


_TOKEN_RE = re.compile(
    r"CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?|[A-Za-z0-9_.:/\\-]+|[\u4e00-\u9fff]",
    re.IGNORECASE,
)


class HashingEmbedding:
    """Feature-hashing vectors for a portable dense lexical-semantic fallback."""

    name = "security-hashing-v1"

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

    def _features(self, text: str) -> list[str]:
        base = [token.lower() for token in _TOKEN_RE.findall(text)]
        joined = " ".join(base)
        # Character n-grams improve matching across Chinese/English wording and
        # preserve security identifiers such as process and rule names.
        grams = [
            joined[index : index + size]
            for size in (2, 3)
            for index in range(max(0, len(joined) - size + 1))
            if not joined[index : index + size].isspace()
        ]
        return base + grams

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vector = [0.0] * self.dimension
            for feature in self._features(text):
                digest = hashlib.blake2b(
                    feature.encode("utf-8"), digest_size=8
                ).digest()
                number = int.from_bytes(digest, "little")
                index = number % self.dimension
                sign = 1.0 if (number >> 8) & 1 else -1.0
                vector[index] += sign
            norm = math.sqrt(sum(value * value for value in vector))
            if norm:
                vector = [value / norm for value in vector]
            vectors.append(vector)
        return vectors


class SentenceTransformerEmbedding:
    """Lazy optional wrapper around sentence-transformers."""

    def __init__(self, model_name: str):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "sentence-transformers is not installed; run "
                "`uv add sentence-transformers` or use "
                "RAG_EMBEDDING_PROVIDER=hashing"
            ) from exc
        self.name = model_name
        self._model = SentenceTransformer(model_name)
        dimension = self._model.get_sentence_embedding_dimension()
        self.dimension = int(dimension or 0)

    def embed(self, texts: list[str]) -> list[list[float]]:
        values = self._model.encode(
            texts, normalize_embeddings=True, show_progress_bar=False
        )
        return [list(map(float, row)) for row in values]


@lru_cache(maxsize=4)
def get_embedding_provider(
    provider: str = "hashing", model_name: str = "BAAI/bge-m3"
) -> EmbeddingProvider:
    if provider.lower() in {"sentence_transformers", "sentence-transformers", "bge"}:
        return SentenceTransformerEmbedding(model_name)
    return HashingEmbedding()

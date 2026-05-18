"""Embedding providers with a deterministic local fallback."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Any

from app.config.settings import settings
from app.utils.logging import get_logger

try:
    from sentence_transformers import SentenceTransformer
except Exception:  # pragma: no cover - optional dependency
    SentenceTransformer = None

try:
    from sentence_transformers import CrossEncoder
except Exception:  # pragma: no cover - optional dependency
    CrossEncoder = None


TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_./:-]+")


def normalize_vector(values: list[float]) -> list[float]:
    magnitude = math.sqrt(sum(value * value for value in values))
    if magnitude == 0:
        return values
    return [value / magnitude for value in values]


def sigmoid_score(value: float) -> float:
    if value >= 0:
        exponent = math.exp(-value)
        return 1.0 / (1.0 + exponent)
    exponent = math.exp(value)
    return exponent / (1.0 + exponent)


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right:
        return 0.0
    length = min(len(left), len(right))
    return sum(left[index] * right[index] for index in range(length))


@dataclass(slots=True)
class EmbeddingDiagnostics:
    backend: str
    model_name: str
    dimension: int
    reranker_enabled: bool


class LocalEmbeddingProvider:
    """Embeds text via sentence-transformers or a deterministic hash fallback."""

    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.dimension = settings.EMBEDDING_DIMENSION
        self.model_name = settings.EMBEDDING_MODEL
        self.backend = "hash-fallback"
        self._model: Any | None = None
        self._reranker: Any | None = None

        if settings.EMBEDDING_BACKEND in {"auto", "sentence-transformers"} and SentenceTransformer is not None:
            try:
                self._model = SentenceTransformer(self.model_name, device=settings.EMBEDDING_DEVICE)
                self.dimension = int(self._model.get_sentence_embedding_dimension())
                self.backend = "sentence-transformers"
            except Exception as exc:  # pragma: no cover - model load is environment-specific
                self.logger.warning("Embedding model load failed: %s", exc)

        if (
            settings.EMBEDDING_BACKEND in {"auto", "sentence-transformers"}
            and settings.ENABLE_RERANKING
            and CrossEncoder is not None
        ):
            try:
                self._reranker = CrossEncoder(settings.RERANK_MODEL)
            except Exception as exc:  # pragma: no cover - model load is environment-specific
                self.logger.warning("Reranker load failed: %s", exc)

    def _hash_embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        tokens = TOKEN_PATTERN.findall(text.lower())
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8")).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimension
            sign = 1.0 if digest[4] % 2 == 0 else -1.0
            vector[bucket] += sign
        return normalize_vector(vector)

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        if self._model is None:
            return [self._hash_embed(text) for text in texts]

        vectors = self._model.encode(
            texts,
            normalize_embeddings=True,
            batch_size=settings.EMBEDDING_BATCH_SIZE,
        )
        return [list(map(float, row)) for row in vectors]

    def rerank(self, query: str, documents: list[str]) -> list[float]:
        if not documents:
            return []
        if self._reranker is None:
            query_vector = self.embed_texts([query])[0]
            doc_vectors = self.embed_texts(documents)
            return [cosine_similarity(query_vector, vector) for vector in doc_vectors]

        pairs = [[query, document] for document in documents]
        scores = self._reranker.predict(pairs)
        return [sigmoid_score(float(score)) for score in scores]

    def diagnostics(self) -> EmbeddingDiagnostics:
        return EmbeddingDiagnostics(
            backend=self.backend,
            model_name=self.model_name,
            dimension=self.dimension,
            reranker_enabled=self._reranker is not None,
        )

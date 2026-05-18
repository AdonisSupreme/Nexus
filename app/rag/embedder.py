"""Embedding service wrappers used by the knowledge index."""

from __future__ import annotations

from app.models.embeddings import LocalEmbeddingProvider


class EmbeddingService:
    """Thin wrapper around the configured embedding provider."""

    def __init__(self) -> None:
        self.provider = LocalEmbeddingProvider()

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return self.provider.embed_texts(texts)

    def rerank(self, query: str, documents: list[str]) -> list[float]:
        return self.provider.rerank(query=query, documents=documents)

    def diagnostics(self) -> dict[str, object]:
        return self.provider.diagnostics().__dict__

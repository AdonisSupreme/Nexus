"""Hybrid retrieval over normalized SOP chunks."""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict

from app.config.settings import settings
from app.models.embeddings import cosine_similarity
from app.rag.chunker import ChunkRecord
from app.rag.indexer import KnowledgeIndexer
from app.utils.logging import get_logger


TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9_./:-]+")


class HybridRetriever:
    """Combine lexical, vector, and reranked evidence retrieval."""

    def __init__(self, indexer: KnowledgeIndexer) -> None:
        self.indexer = indexer
        self.logger = get_logger(__name__)
        self._doc_freqs: Counter[str] = Counter()
        self._doc_lengths: dict[str, int] = {}
        self._tokens_by_chunk: dict[str, list[str]] = {}
        self._avg_doc_length: float = 0.0

    def rebuild(self) -> None:
        self._doc_freqs.clear()
        self._doc_lengths.clear()
        self._tokens_by_chunk.clear()

        for chunk in self.indexer.chunks:
            tokens = self.tokenize(chunk.text)
            self._tokens_by_chunk[chunk.chunk_id] = tokens
            self._doc_lengths[chunk.chunk_id] = len(tokens)
            for token in set(tokens):
                self._doc_freqs[token] += 1

        total_length = sum(self._doc_lengths.values())
        self._avg_doc_length = total_length / len(self._doc_lengths) if self._doc_lengths else 0.0

    def tokenize(self, text: str) -> list[str]:
        return TOKEN_PATTERN.findall(text.lower())

    def _bm25(self, query_tokens: list[str], chunk: ChunkRecord) -> float:
        tokens = self._tokens_by_chunk.get(chunk.chunk_id, [])
        frequencies = Counter(tokens)
        score = 0.0
        doc_length = self._doc_lengths.get(chunk.chunk_id, 1)
        total_docs = max(len(self._doc_lengths), 1)
        avg_doc_length = self._avg_doc_length or 1.0

        for token in query_tokens:
            tf = frequencies.get(token, 0)
            if tf == 0:
                continue
            df = self._doc_freqs.get(token, 0)
            idf = math.log((total_docs - df + 0.5) / (df + 0.5) + 1)
            numerator = tf * (1.5 + 1)
            denominator = tf + 1.5 * (1 - 0.75 + 0.75 * (doc_length / avg_doc_length))
            score += idf * (numerator / denominator)
        return score

    def search(self, query: str, top_k: int | None = None) -> list[ChunkRecord]:
        if not self.indexer.chunks:
            return []
        top_k = top_k or settings.MAX_SOP_RETRIEVAL
        query_tokens = self.tokenize(query)
        query_vector = self.indexer.embedding_service.embed_texts([query])[0]

        lexical_scores = sorted(
            ((chunk.chunk_id, self._bm25(query_tokens, chunk)) for chunk in self.indexer.chunks),
            key=lambda item: item[1],
            reverse=True,
        )
        vector_scores = sorted(
            (
                (chunk.chunk_id, cosine_similarity(query_vector, chunk.vector or []))
                for chunk in self.indexer.chunks
            ),
            key=lambda item: item[1],
            reverse=True,
        )

        fused_scores: defaultdict[str, float] = defaultdict(float)
        for ranking in (lexical_scores[: top_k * 4], vector_scores[: top_k * 4]):
            for rank, (chunk_id, _score) in enumerate(ranking, start=1):
                fused_scores[chunk_id] += 1.0 / (60 + rank)

        by_id = {chunk.chunk_id: chunk for chunk in self.indexer.chunks}
        candidates = sorted(
            ((chunk_id, score) for chunk_id, score in fused_scores.items()),
            key=lambda item: item[1],
            reverse=True,
        )[: top_k * 3]
        documents = [by_id[chunk_id].text for chunk_id, _ in candidates]
        rerank_scores = self.indexer.embedding_service.rerank(query=query, documents=documents)

        ranked: list[ChunkRecord] = []
        for (chunk_id, base_score), rerank_score in zip(candidates, rerank_scores):
            chunk = by_id[chunk_id]
            combined = (base_score * 0.4) + (float(rerank_score) * 0.6)
            chunk.score = round(max(0.0, min(1.0, combined)), 6)
            ranked.append(chunk)

        ranked.sort(key=lambda item: item.score, reverse=True)
        return ranked[:top_k]

"""Build evidence packs and citations from retrieved chunks."""

from __future__ import annotations

from collections import defaultdict

from app.config.settings import settings
from app.rag.chunker import ChunkRecord
from app.schemas.response_schema import Citation, RetrievedEvidence


class ContextBuilder:
    """Convert retrieved chunk records into structured evidence."""

    def build(self, chunks: list[ChunkRecord]) -> tuple[list[RetrievedEvidence], list[Citation]]:
        chunks = [chunk for chunk in chunks if (chunk.score or 0.0) > 0.0]
        if not chunks:
            return [], []

        grouped: dict[str, list[ChunkRecord]] = defaultdict(list)
        for chunk in chunks:
            grouped[chunk.sop_id].append(chunk)

        evidence: list[RetrievedEvidence] = []
        citations: list[Citation] = []

        for sop_id, items in grouped.items():
            items.sort(key=lambda item: item.score, reverse=True)
            top = items[0]
            evidence.append(
                RetrievedEvidence(
                    sop_id=sop_id,
                    title=top.title,
                    class_code=top.class_code,
                    score=round(sum(item.score for item in items) / len(items), 6),
                    sections=sorted({item.section for item in items}),
                    excerpts=[item.text for item in items[:3]],
                    alignment_status=", ".join(top.alignment_status),
                )
            )

            for item in items[: settings.MAX_EVIDENCE_CITATIONS]:
                if (item.score or 0.0) <= 0.0:
                    continue
                citations.append(
                    Citation(
                        sop_id=item.sop_id,
                        title=item.title,
                        section=item.section,
                        excerpt=item.text,
                        score=item.score,
                        source_path=item.source_path,
                    )
                )

        citations.sort(key=lambda item: item.score, reverse=True)
        evidence.sort(key=lambda item: item.score, reverse=True)
        return evidence, citations[: settings.MAX_EVIDENCE_CITATIONS]

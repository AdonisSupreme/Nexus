"""Chunking for normalized SOPs."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable

from app.schemas.sop_schema import ArtifactType, NormalizedSOP, ProcedureStep


@dataclass(slots=True)
class ChunkRecord:
    chunk_id: str
    sop_id: str
    title: str
    class_code: str
    section: str
    sequence: int
    text: str
    safety_critical: bool
    markers: list[str]
    alignment_status: list[str]
    source_path: str
    score: float = 0.0
    vector: list[float] | None = None

    def to_dict(self, include_vector: bool = True) -> dict[str, object]:
        payload = asdict(self)
        if not include_vector:
            payload.pop("vector", None)
        return payload


class SOPChunker:
    """Convert normalized SOPs into retrievable evidence chunks."""

    def __init__(self, max_chunk_size: int = 1000) -> None:
        self.max_chunk_size = max_chunk_size

    def chunk_sop(self, sop: NormalizedSOP) -> list[ChunkRecord]:
        chunks: list[ChunkRecord] = []
        chunks.append(
            ChunkRecord(
                chunk_id=f"{sop.id}:description:0",
                sop_id=sop.id,
                title=sop.title,
                class_code=sop.class_code.value,
                section="description",
                sequence=0,
                text=self._description_text(sop),
                safety_critical=False,
                markers=[],
                alignment_status=[status.value for status in sop.alignment_status],
                source_path=sop.provenance.source_path,
            )
        )

        for section_name, steps in self._section_iterator(sop):
            for step in steps:
                chunks.extend(self._chunk_step(sop=sop, section_name=section_name, step=step))

        return chunks

    def _section_iterator(self, sop: NormalizedSOP) -> Iterable[tuple[str, list[ProcedureStep]]]:
        yield "preconditions", sop.preconditions
        yield "symptoms", sop.symptoms
        yield "checks", sop.checks
        yield "verification_steps", sop.verification_steps
        yield "actions", sop.actions
        yield "rollback", sop.rollback
        yield "escalation", sop.escalation
        yield "notes", sop.notes

    def _description_text(self, sop: NormalizedSOP) -> str:
        services = ", ".join(sop.services) if sop.services else "none"
        environments = ", ".join(sop.environments) if sop.environments else "none"
        aliases = ", ".join(sop.aliases) if sop.aliases else "none"
        return (
            f"Title: {sop.title}\n"
            f"Class: {sop.class_code.value}\n"
            f"Severity: {sop.severity.value}\n"
            f"Services: {services}\n"
            f"Environments: {environments}\n"
            f"Aliases: {aliases}"
        )

    def _chunk_step(self, sop: NormalizedSOP, section_name: str, step: ProcedureStep) -> list[ChunkRecord]:
        text = step.text.strip()
        markers = list(step.markers)
        is_atomic = step.atomic or step.safety_critical or any(
            marker in {ArtifactType.SQL.value, ArtifactType.COMMAND.value, ArtifactType.URL.value, ArtifactType.IP_ADDRESS.value}
            for marker in markers
        )

        if is_atomic or len(text) <= self.max_chunk_size:
            return [
                ChunkRecord(
                    chunk_id=f"{sop.id}:{section_name}:{step.sequence}",
                    sop_id=sop.id,
                    title=sop.title,
                    class_code=sop.class_code.value,
                    section=section_name,
                    sequence=step.sequence,
                    text=text,
                    safety_critical=step.safety_critical,
                    markers=markers,
                    alignment_status=[status.value for status in sop.alignment_status],
                    source_path=sop.provenance.source_path,
                )
            ]

        result: list[ChunkRecord] = []
        start = 0
        part = 0
        while start < len(text):
            end = min(start + self.max_chunk_size, len(text))
            while end < len(text) and text[end - 1] not in {".", ";", "\n"} and end > start + 150:
                end -= 1
            chunk_text = text[start:end].strip()
            if chunk_text:
                result.append(
                    ChunkRecord(
                        chunk_id=f"{sop.id}:{section_name}:{step.sequence}:{part}",
                        sop_id=sop.id,
                        title=sop.title,
                        class_code=sop.class_code.value,
                        section=section_name,
                        sequence=step.sequence,
                        text=chunk_text,
                        safety_critical=step.safety_critical,
                        markers=markers,
                        alignment_status=[status.value for status in sop.alignment_status],
                        source_path=sop.provenance.source_path,
                    )
                )
                part += 1
            start = end
        return result

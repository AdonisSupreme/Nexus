"""Knowledge normalization and index building."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from app.config.settings import settings
from app.rag.chunker import ChunkRecord, SOPChunker
from app.rag.embedder import EmbeddingService
from app.schemas.response_schema import AlignmentReport
from app.schemas.sop_schema import (
    AlignmentStatus,
    ArtifactType,
    EvidenceArtifact,
    NormalizedSOP,
    SOPBatchValidationResult,
    SOPClass,
    SOPProvenance,
    SOPValidationResult,
    Severity,
    ProcedureStep,
)
from app.utils.audit import audit_logger
from app.utils.logging import get_logger


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
THRESHOLD_PATTERN = re.compile(r"\b(?:>|<|>=|<=)?\s?\d+(?:\.\d+)?\s?(?:%|percent|seconds?|minutes?|hours?)\b", re.IGNORECASE)
COMMAND_HINTS = ("ssh ", "df -", "du -", "ps -", "netstat", "tail ", "grep ", "systemctl ", "service ")
SQL_HINTS = ("select ", "update ", "insert ", "delete ", "commit;", "alter ")
OWNER_HINTS = ("team", "manager", "dba", "head ict", "support", "operations", "vendor")
RESERVED_FIELDS = {"id", "class", "title", "severity", "services", "environments", "aliases"}


class KnowledgeIndexer:
    """Load raw SOPs, normalize them, and build the retrieval index."""

    def __init__(self, embedding_service: EmbeddingService | None = None) -> None:
        self.logger = get_logger(__name__)
        self.embedding_service = embedding_service or EmbeddingService()
        self.chunker = SOPChunker()
        self.normalized_sops: dict[str, NormalizedSOP] = {}
        self.chunks: list[ChunkRecord] = []
        self.last_ingest_at: datetime | None = None
        self.last_ingest_warnings: list[str] = []
        self.last_source_file_count: int = 0

    def _iter_source_files(self) -> list[Path]:
        files: list[Path] = []
        for directory in settings.raw_knowledge_dirs:
            if not directory.exists():
                continue
            files.extend(sorted(directory.rglob("*.yaml")))
            files.extend(sorted(directory.rglob("*.yml")))
        return files

    def _read_yaml(self, path: Path) -> dict[str, Any]:
        with open(path, "r", encoding="utf-8") as handle:
            raw_text = handle.read()

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as exc:
            lines = raw_text.lstrip("\ufeff").splitlines()
            first_content_index = next((index for index, line in enumerate(lines) if line.strip()), None)
            if first_content_index is None:
                raise ValueError("YAML document is empty") from exc

            first_line = lines[first_content_index].strip()
            is_heading_line = ":" not in first_line and first_content_index + 1 < len(lines)
            if not is_heading_line:
                raise

            candidate_text = "\n".join(lines[first_content_index + 1 :])
            data = yaml.safe_load(candidate_text)

        if not isinstance(data, dict):
            raise ValueError("YAML document must be a mapping")
        return data

    def _unwrap_document(self, data: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
        if len(data) == 1:
            key, value = next(iter(data.items()))
            if isinstance(value, dict) and any(field in value for field in ("id", "class", "title")):
                return value, str(key)
        return data, None

    def _normalize_class_code(self, payload: dict[str, Any], sop_id: str) -> SOPClass:
        raw_class = str(payload.get("class") or payload.get("class_code") or "").strip().upper()
        if raw_class.startswith("SOP-"):
            raw_class = raw_class[-1]
        if not raw_class and sop_id.upper().startswith("SOP-"):
            parts = sop_id.split("-")
            if len(parts) > 1:
                raw_class = parts[1][:1].upper()
        try:
            return SOPClass(raw_class)
        except Exception as exc:
            raise ValueError(f"Unsupported SOP class for {sop_id}: {raw_class}") from exc

    def _normalize_severity(self, value: Any) -> Severity:
        raw = str(value or "medium").strip().lower()
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        if raw not in mapping:
            return Severity.MEDIUM
        return mapping[raw]

    def _format_key(self, key: str) -> str:
        return key.replace("_", " ").replace("-", " ").strip()

    def _section_for_key(self, key: str) -> str:
        lowered = key.lower()
        if lowered in {"pre_checks", "preconditions"} or ("pre" in lowered and "check" in lowered):
            return "preconditions"
        if "symptom" in lowered:
            return "symptoms"
        if lowered == "checks" or lowered.endswith("_checks") or "check" in lowered:
            return "checks"
        if any(marker in lowered for marker in ("verification", "validation", "health", "testing", "monitoring")):
            return "verification_steps"
        if any(marker in lowered for marker in ("recommended_action", "procedure", "mitigation", "strategy")):
            return "actions"
        if "rollback" in lowered:
            return "rollback"
        if "escalat" in lowered:
            return "escalation"
        return "notes"

    def _flatten_value(self, value: Any, prefix: str = "") -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [f"{prefix}: {value}" if prefix else value]
        if isinstance(value, (int, float, bool)):
            return [f"{prefix}: {value}" if prefix else str(value)]
        if isinstance(value, list):
            flattened: list[str] = []
            for item in value:
                flattened.extend(self._flatten_value(item, prefix=prefix))
            return flattened
        if isinstance(value, dict):
            flattened: list[str] = []
            for key, item in value.items():
                key_name = self._format_key(str(key))
                next_prefix = prefix
                if key_name.lower() not in {"steps", "items", "checks"}:
                    next_prefix = f"{prefix}: {key_name}" if prefix else key_name
                flattened.extend(self._flatten_value(item, prefix=next_prefix))
            return flattened
        return [f"{prefix}: {value}" if prefix else str(value)]

    def _markers_for_text(self, text: str) -> list[str]:
        lowered = text.lower()
        markers: list[str] = []
        if any(lowered.startswith(hint) or hint in lowered for hint in SQL_HINTS):
            markers.append(ArtifactType.SQL.value)
        if any(hint in lowered for hint in COMMAND_HINTS):
            markers.append(ArtifactType.COMMAND.value)
        if URL_PATTERN.search(text):
            markers.append(ArtifactType.URL.value)
        if IP_PATTERN.search(text):
            markers.append(ArtifactType.IP_ADDRESS.value)
        if THRESHOLD_PATTERN.search(text):
            markers.append(ArtifactType.THRESHOLD.value)
        return sorted(set(markers))

    def _extract_artifacts(self, step: ProcedureStep) -> list[EvidenceArtifact]:
        artifacts: list[EvidenceArtifact] = []
        for match in URL_PATTERN.findall(step.text):
            artifacts.append(EvidenceArtifact(type=ArtifactType.URL, value=match, source_section=step.source_section, sequence=step.sequence))
        for match in IP_PATTERN.findall(step.text):
            artifacts.append(EvidenceArtifact(type=ArtifactType.IP_ADDRESS, value=match, source_section=step.source_section, sequence=step.sequence))
        if ArtifactType.SQL.value in step.markers:
            artifacts.append(EvidenceArtifact(type=ArtifactType.SQL, value=step.text, source_section=step.source_section, sequence=step.sequence))
        elif ArtifactType.COMMAND.value in step.markers:
            artifacts.append(EvidenceArtifact(type=ArtifactType.COMMAND, value=step.text, source_section=step.source_section, sequence=step.sequence))
        for match in THRESHOLD_PATTERN.findall(step.text):
            artifacts.append(EvidenceArtifact(type=ArtifactType.THRESHOLD, value=match, source_section=step.source_section, sequence=step.sequence))
        return artifacts

    def _extract_owners(self, steps: list[ProcedureStep]) -> list[str]:
        owners: set[str] = set()
        for step in steps:
            lowered = step.text.lower()
            if any(hint in lowered for hint in OWNER_HINTS):
                owners.add(step.text)
        return sorted(owners)

    def normalize_file(self, path: Path) -> NormalizedSOP:
        raw_data = self._read_yaml(path)
        payload, wrapper_key = self._unwrap_document(raw_data)
        sop_id = str(payload.get("id") or path.stem).strip()
        class_code = self._normalize_class_code(payload, sop_id)
        normalized_at = datetime.utcnow()

        sections: dict[str, list[ProcedureStep]] = defaultdict(list)
        artifacts: list[EvidenceArtifact] = []
        sequence_counter: Counter[str] = Counter()

        for key, value in payload.items():
            if key in RESERVED_FIELDS:
                continue
            section_name = self._section_for_key(key)
            lines = self._flatten_value(value)
            for line in lines:
                text = line.strip()
                if not text:
                    continue
                sequence_counter[section_name] += 1
                markers = self._markers_for_text(text)
                safety_critical = section_name in {"actions", "rollback", "escalation"} and bool(markers or class_code in {SOPClass.INCIDENT_RESPONSE, SOPClass.DISASTER_RECOVERY})
                step = ProcedureStep(
                    text=text,
                    sequence=sequence_counter[section_name],
                    source_section=self._format_key(key),
                    atomic=bool(markers),
                    safety_critical=safety_critical,
                    markers=markers,
                )
                sections[section_name].append(step)
                artifacts.extend(self._extract_artifacts(step))

        raw_text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        source_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        provenance = SOPProvenance(
            source_path=str(path),
            source_directory=str(path.parent),
            source_hash=source_hash,
            wrapper_key=wrapper_key,
            ingested_at=normalized_at,
            normalized_at=normalized_at,
        )

        sop = NormalizedSOP(
            id=sop_id,
            class_code=class_code,
            title=str(payload.get("title") or sop_id).strip(),
            severity=self._normalize_severity(payload.get("severity")),
            services=payload.get("services", []),
            environments=payload.get("environments", []),
            aliases=payload.get("aliases", []),
            preconditions=sections.get("preconditions", []),
            symptoms=sections.get("symptoms", []),
            checks=sections.get("checks", []),
            verification_steps=sections.get("verification_steps", []),
            actions=sections.get("actions", []),
            rollback=sections.get("rollback", []),
            escalation=sections.get("escalation", []),
            notes=sections.get("notes", []),
            systems=payload.get("services", []),
            owners=self._extract_owners(sections.get("escalation", []) + sections.get("notes", [])),
            artifacts=artifacts,
            alignment_status=[
                AlignmentStatus.VERIFIED_FROM_CORPUS,
                AlignmentStatus.PENDING_MANUAL_RECONCILIATION,
            ],
            last_verified_at=normalized_at,
            provenance=provenance,
            source_sections=sorted({step.source_section for values in sections.values() for step in values}),
        )

        self._write_snapshot(path=path, raw_data=payload, sop=sop)
        return sop

    def _write_snapshot(self, path: Path, raw_data: dict[str, Any], sop: NormalizedSOP) -> None:
        raw_target = settings.RAW_SNAPSHOT_DIR / f"{path.stem}.json"
        with open(raw_target, "w", encoding="utf-8") as handle:
            json.dump(raw_data, handle, indent=2, ensure_ascii=False)

        normalized_target = settings.NORMALIZED_DIR / f"{sop.id}.json"
        with open(normalized_target, "w", encoding="utf-8") as handle:
            json.dump(sop.to_dict(), handle, indent=2, ensure_ascii=False)

    def validate_sources(self) -> SOPBatchValidationResult:
        results: list[SOPValidationResult] = []
        valid = 0
        invalid = 0
        for path in self._iter_source_files():
            try:
                sop = self.normalize_file(path)
                warnings: list[str] = []
                if AlignmentStatus.PENDING_MANUAL_RECONCILIATION in sop.alignment_status:
                    warnings.append("Manual reconciliation pending.")
                results.append(
                    SOPValidationResult(
                        valid=True,
                        sop_id=sop.id,
                        file_path=str(path),
                        warnings=warnings,
                    )
                )
                valid += 1
            except Exception as exc:
                results.append(
                    SOPValidationResult(
                        valid=False,
                        sop_id=path.stem,
                        file_path=str(path),
                        errors=[str(exc)],
                    )
                )
                invalid += 1

        return SOPBatchValidationResult(
            total_sops=len(results),
            valid_sops=valid,
            invalid_sops=invalid,
            results=results,
        )

    def ingest(self) -> dict[str, Any]:
        normalized: dict[str, NormalizedSOP] = {}
        warnings: list[str] = []
        source_files = self._iter_source_files()
        self.last_source_file_count = len(source_files)
        for path in source_files:
            try:
                sop = self.normalize_file(path)
                normalized[sop.id] = sop
            except Exception as exc:
                warning = f"Failed to normalize {path.name}: {exc}"
                self.logger.warning(warning)
                warnings.append(warning)

        self.normalized_sops = normalized
        self.chunks = []
        for sop in normalized.values():
            self.chunks.extend(self.chunker.chunk_sop(sop))

        vectors = self.embedding_service.embed_texts([chunk.text for chunk in self.chunks])
        for chunk, vector in zip(self.chunks, vectors):
            chunk.vector = vector

        self.last_ingest_at = datetime.utcnow()
        self.last_ingest_warnings = warnings
        self._persist_outputs()
        report = self.generate_alignment_report()
        audit_logger.log_system_event(
            event="knowledge_ingest",
            component="indexer",
            details={
                "sops": len(self.normalized_sops),
                "chunks": len(self.chunks),
                "warnings": warnings,
            },
        )
        return {
            "sops": len(self.normalized_sops),
            "chunks": len(self.chunks),
            "generated_at": self.last_ingest_at.isoformat() + "Z",
            "warnings": warnings,
            "alignment_report": report.model_dump(mode="json"),
        }

    def _persist_outputs(self) -> None:
        with open(settings.normalized_output_path, "w", encoding="utf-8") as handle:
            json.dump(
                {sop_id: sop.to_dict() for sop_id, sop in self.normalized_sops.items()},
                handle,
                indent=2,
                ensure_ascii=False,
            )

        with open(settings.chunk_output_path, "w", encoding="utf-8") as handle:
            json.dump([chunk.to_dict() for chunk in self.chunks], handle, indent=2, ensure_ascii=False)

        with open(settings.vector_index_path, "w", encoding="utf-8") as handle:
            json.dump([chunk.to_dict() for chunk in self.chunks], handle, indent=2, ensure_ascii=False)

        report = self.generate_alignment_report()
        with open(settings.alignment_report_path, "w", encoding="utf-8") as handle:
            json.dump(report.model_dump(mode="json"), handle, indent=2, ensure_ascii=False)

    def load_from_disk(self) -> bool:
        if not settings.normalized_output_path.exists() or not settings.chunk_output_path.exists():
            return False
        with open(settings.normalized_output_path, "r", encoding="utf-8") as handle:
            normalized_data = json.load(handle)
        with open(settings.chunk_output_path, "r", encoding="utf-8") as handle:
            chunk_data = json.load(handle)

        self.normalized_sops = {
            sop_id: NormalizedSOP.model_validate(data)
            for sop_id, data in normalized_data.items()
        }
        self.chunks = [ChunkRecord(**item) for item in chunk_data]
        if settings.alignment_report_path.exists():
            with open(settings.alignment_report_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
            self.last_ingest_at = datetime.fromisoformat(report["generated_at"].replace("Z", "+00:00")).replace(tzinfo=None)
        return True

    def generate_alignment_report(self) -> AlignmentReport:
        class_counts = Counter(sop.class_code.value for sop in self.normalized_sops.values())
        status_counts = Counter(status.value for sop in self.normalized_sops.values() for status in sop.alignment_status)
        return AlignmentReport(
            generated_at=self.last_ingest_at or datetime.utcnow(),
            total_documents=self.last_source_file_count or len(self._iter_source_files()),
            normalized_documents=len(self.normalized_sops),
            classes=dict(class_counts),
            statuses=dict(status_counts),
            source_directories=[str(directory) for directory in settings.raw_knowledge_dirs],
            warnings=["Manual reconciliation is still pending for all corpus-derived SOPs.", *self.last_ingest_warnings],
        )

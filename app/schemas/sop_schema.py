"""Schemas for normalized SOPs and ingestion reporting."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SOPClass(str, Enum):
    INCIDENT_RESPONSE = "A"
    SERVICE_CONTROL = "B"
    ENVIRONMENT_MANAGEMENT = "C"
    DISASTER_RECOVERY = "D"
    VERIFICATION_HEALTH = "E"
    ADMINISTRATIVE = "F"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlignmentStatus(str, Enum):
    VERIFIED_FROM_CORPUS = "verified_from_corpus"
    PENDING_MANUAL_RECONCILIATION = "pending_manual_reconciliation"
    MANUALLY_ALIGNED = "manually_aligned"
    DEPRECATED = "deprecated"


class ArtifactType(str, Enum):
    COMMAND = "command"
    SQL = "sql"
    URL = "url"
    IP_ADDRESS = "ip_address"
    THRESHOLD = "threshold"
    NOTE = "note"


class ProcedureStep(BaseModel):
    text: str = Field(..., min_length=1)
    sequence: int = Field(..., ge=1)
    source_section: str
    atomic: bool = True
    safety_critical: bool = False
    markers: list[str] = Field(default_factory=list)


class EvidenceArtifact(BaseModel):
    type: ArtifactType
    value: str
    source_section: str
    sequence: int


class SOPProvenance(BaseModel):
    source_path: str
    source_directory: str
    source_format: str = "yaml"
    source_hash: str
    wrapper_key: str | None = None
    ingested_at: datetime
    normalized_at: datetime


class NormalizedSOP(BaseModel):
    id: str = Field(..., min_length=3)
    class_code: SOPClass
    title: str = Field(..., min_length=5, max_length=300)
    severity: Severity
    version: int = 1
    services: list[str] = Field(default_factory=list)
    environments: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    preconditions: list[ProcedureStep] = Field(default_factory=list)
    symptoms: list[ProcedureStep] = Field(default_factory=list)
    checks: list[ProcedureStep] = Field(default_factory=list)
    verification_steps: list[ProcedureStep] = Field(default_factory=list)
    actions: list[ProcedureStep] = Field(default_factory=list)
    rollback: list[ProcedureStep] = Field(default_factory=list)
    escalation: list[ProcedureStep] = Field(default_factory=list)
    notes: list[ProcedureStep] = Field(default_factory=list)
    systems: list[str] = Field(default_factory=list)
    owners: list[str] = Field(default_factory=list)
    artifacts: list[EvidenceArtifact] = Field(default_factory=list)
    alignment_status: list[AlignmentStatus] = Field(default_factory=list)
    last_verified_at: datetime
    provenance: SOPProvenance
    source_sections: list[str] = Field(default_factory=list)

    @field_validator("services", "environments", "aliases", "systems", "owners", mode="before")
    @classmethod
    def ensure_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return [str(value).strip()]

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class SOPValidationResult(BaseModel):
    valid: bool
    sop_id: str
    file_path: str
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SOPBatchValidationResult(BaseModel):
    total_sops: int
    valid_sops: int
    invalid_sops: int
    results: list[SOPValidationResult]

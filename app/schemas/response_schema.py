"""Request and response contracts for the operational intelligence API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.intent_schema import ClassificationResult


class UserContext(BaseModel):
    user_id: str | None = None
    username: str | None = None
    role: str | None = None
    shift: str | None = None
    department: str | None = None


class SystemContext(BaseModel):
    environment: str | None = None
    affected_systems: list[str] = Field(default_factory=list)
    urgency: str | None = None
    incident_id: str | None = None


class ChatRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=5000)
    user_context: UserContext = Field(default_factory=UserContext)
    system_context: SystemContext = Field(default_factory=SystemContext)
    scope: str = Field(default="all")
    stream: bool = Field(default=False)
    trace: bool = Field(default=False)


class Citation(BaseModel):
    sop_id: str
    title: str
    section: str
    excerpt: str
    score: float
    source_path: str


class RetrievedEvidence(BaseModel):
    sop_id: str
    title: str
    class_code: str
    score: float
    sections: list[str]
    excerpts: list[str]
    alignment_status: str


class ChatResponse(BaseModel):
    answer: str
    intent: ClassificationResult
    confidence: float = Field(..., ge=0.0, le=1.0)
    citations: list[Citation] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    retrieved_sops: list[RetrievedEvidence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    trace_id: str
    trace: dict[str, Any] | None = None


class SOPSearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=5000)
    top_k: int = Field(default=5, ge=1, le=25)
    min_score: float = Field(default=0.0, ge=0.0, le=1.0)


class SOPGraphNode(BaseModel):
    chunk_id: str
    sop_id: str
    section: str
    sequence: int
    text: str
    score: float | None = None


class KnowledgeJob(BaseModel):
    job_id: str
    kind: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class IndexStats(BaseModel):
    sops: int
    chunks: int
    vector_backend: str
    cache_backend: str
    normalized_at: datetime | None = None


class EngineState(BaseModel):
    status: str
    environment: str
    providers: dict[str, Any]
    index: IndexStats
    cache: dict[str, Any]
    circuit_breaker: dict[str, Any]
    last_ingest_at: datetime | None = None


class AlignmentReport(BaseModel):
    generated_at: datetime
    total_documents: int
    normalized_documents: int
    classes: dict[str, int]
    statuses: dict[str, int]
    source_directories: list[str]
    warnings: list[str] = Field(default_factory=list)

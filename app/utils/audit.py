"""Append-only audit logging for compliance and traceability."""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.config.settings import settings
from app.utils.logging import get_logger


class AuditLogger:
    """Structured audit logger."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("sentinelops.audit")
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)

        settings.LOGS_DIR.mkdir(parents=True, exist_ok=True)
        if not self.logger.handlers:
            handler = logging.handlers.RotatingFileHandler(
                filename=settings.audit_file_path,
                maxBytes=settings.AUDIT_LOG_MAX_SIZE,
                backupCount=settings.AUDIT_LOG_BACKUP_COUNT,
                encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self.logger.addHandler(handler)

    def _record(
        self,
        event_type: str,
        user: str,
        details: dict[str, Any],
        success: bool = True,
    ) -> dict[str, Any]:
        return {
            "audit_id": str(uuid4()),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "user": user,
            "environment": settings.ENVIRONMENT,
            "success": success,
            "details": details,
        }

    def log(self, event_type: str, user: str, details: dict[str, Any], success: bool = True) -> str:
        record = self._record(event_type=event_type, user=user, details=details, success=success)
        self.logger.info(json.dumps(record, ensure_ascii=False))
        get_logger(__name__).info(
            "AUDIT %s user=%s success=%s id=%s",
            event_type,
            user,
            success,
            record["audit_id"],
        )
        return record["audit_id"]

    def log_sop_retrieval(
        self,
        user: str,
        query: str,
        intent: str,
        sop_ids: list[str],
        confidence: float,
        response_id: str | None = None,
    ) -> str:
        return self.log(
            event_type="sop_retrieval",
            user=user,
            details={
                "query": query,
                "intent": intent,
                "sop_ids": sop_ids,
                "confidence": confidence,
                "response_id": response_id,
            },
            success=bool(sop_ids),
        )

    def log_intent_classification(
        self,
        user: str,
        query: str,
        detected_intent: str,
        confidence: float,
        rejected: bool = False,
    ) -> str:
        return self.log(
            event_type="intent_classification",
            user=user,
            details={
                "query": query,
                "detected_intent": detected_intent,
                "confidence": confidence,
                "rejected": rejected,
            },
            success=not rejected,
        )

    def log_validation_failure(
        self,
        user: str,
        validation_type: str,
        reason: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        return self.log(
            event_type="validation_failure",
            user=user,
            details={
                "validation_type": validation_type,
                "reason": reason,
                "context": context or {},
            },
            success=False,
        )

    def log_system_event(
        self,
        event: str,
        component: str,
        details: dict[str, Any],
        severity: str = "INFO",
    ) -> str:
        return self.log(
            event_type="system_event",
            user="system",
            details={
                "event": event,
                "component": component,
                "severity": severity,
                "details": details,
            },
            success=severity not in {"ERROR", "CRITICAL"},
        )

    def log_security_event(
        self,
        event: str,
        user: str,
        details: dict[str, Any],
        severity: str = "MEDIUM",
    ) -> str:
        return self.log(
            event_type="security_event",
            user=user,
            details={
                "event": event,
                "severity": severity,
                "details": details,
            },
            success=False,
        )


audit_logger = AuditLogger()

"""
Audit logger for Erithm verdicts.

Logs every verdict as an OTel span, creating an audit trail by construction.
Content is stored in span events (not attributes) and redacted before export,
per PRD Section 7 requirements.

Design:
    - Each verdict produces exactly one audit span.
    - Span attributes contain only safe metadata (verdict type, confidence,
      policy rule, OWASP reference).
    - Content (taint paths, reasons) goes in span events.
    - All content is redacted via the ContentRedactor before event creation.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from erithm.utils.otel_compat import OTelGenAIMapping as M
from erithm.utils.redactor import ContentRedactor
from erithm.verdict.models import Verdict, AnalysisResult

logger = logging.getLogger(__name__)


class AuditLogger:
    """Logs Erithm verdicts as structured audit records.

    Produces audit entries that can be exported as OTel spans for
    integration with standard trace viewers (Jaeger, Grafana Tempo, etc.).
    Also logs to Python's logging framework for immediate visibility.

    Every verdict (block/warn/allow) is logged — this creates an audit
    trail by construction, not bolted on later.

    Example:
        audit = AuditLogger()
        audit.log_result(analysis_result)
    """

    def __init__(
        self,
        redactor: ContentRedactor | None = None,
        enable_otel_export: bool = False,
    ) -> None:
        """Initialize the audit logger.

        Args:
            redactor: Content redactor for PII/secret masking.
                Uses default redactor if None.
            enable_otel_export: Whether to export audit spans via OTel.
                Defaults to False (log-only mode for v1).
        """
        self._redactor = redactor or ContentRedactor()
        self._enable_otel = enable_otel_export
        self._audit_records: list[dict[str, Any]] = []

    def log_verdict(self, verdict: Verdict) -> dict[str, Any]:
        """Log a single verdict as an audit record.

        Args:
            verdict: The verdict to log.

        Returns:
            Structured audit record dictionary.
        """
        record = {
            "timestamp": time.time(),
            "event": "erithm.verdict",
            "attributes": {
                M.ERITHM_VERDICT_TYPE: verdict.verdict_type.value,
                M.ERITHM_TAINT_LABEL: verdict.taint_label,
                M.ERITHM_CONFIDENCE: str(verdict.confidence),
                M.ERITHM_CLASSIFIER: verdict.classifier,
                M.ERITHM_POLICY_RULE: verdict.policy_rule,
                "trace_id": verdict.trace_id,
                "tool_name": verdict.tool_name,
            },
            "events": [
                {
                    "name": "erithm.verdict.detail",
                    "attributes": {
                        "reason": self._redactor.redact(verdict.reason),
                        "taint_path": json.dumps(verdict.taint_path),
                        "owasp_ref": verdict.owasp_ref,
                    },
                }
            ],
        }

        self._audit_records.append(record)

        # Log to Python logger
        log_func = self._get_log_func(verdict)
        log_func(
            "AUDIT: %s | tool=%s | confidence=%.2f | rule=%s | %s",
            verdict.verdict_type.value.upper(),
            verdict.tool_name,
            verdict.confidence,
            verdict.policy_rule,
            self._redactor.create_snippet(verdict.reason, max_length=100),
        )

        return record

    def log_result(self, result: AnalysisResult) -> list[dict[str, Any]]:
        """Log all verdicts in an analysis result.

        Args:
            result: The analysis result to log.

        Returns:
            List of audit record dictionaries.
        """
        records = []

        for verdict in result.verdicts:
            record = self.log_verdict(verdict)
            records.append(record)

        # Log summary
        logger.info(
            "AUDIT SUMMARY: trace=%s | overall=%s | violations=%d | "
            "tainted=%d/%d | time=%.1fms",
            result.trace_id[:8] if result.trace_id else "unknown",
            result.overall_verdict.value,
            result.violations_found,
            result.tainted_calls,
            result.total_tool_calls,
            result.analysis_time_ms,
        )

        return records

    def get_audit_trail(self) -> list[dict[str, Any]]:
        """Return all audit records logged in this session.

        Returns:
            List of structured audit record dictionaries.
        """
        return list(self._audit_records)

    def export_audit_trail(self) -> str:
        """Export the audit trail as a JSON string.

        All content in the export is redacted.

        Returns:
            JSON-serialized audit trail string.
        """
        return json.dumps(self._audit_records, indent=2, default=str)

    def clear(self) -> None:
        """Clear the in-memory audit trail."""
        self._audit_records.clear()

    @staticmethod
    def _get_log_func(verdict: Verdict):
        """Get the appropriate logging function for a verdict severity.

        Args:
            verdict: The verdict to log.

        Returns:
            Logging function (logger.warning, logger.info, etc.).
        """
        if verdict.verdict_type.should_block:
            return logger.warning
        if verdict.verdict_type.should_warn:
            return logger.warning
        return logger.info

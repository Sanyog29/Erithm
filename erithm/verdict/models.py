"""
Verdict data models.

Defines the structured output of the Erithm verdict engine. Each verdict
represents an enforcement decision with full provenance information for
audit logging and compliance traceability.

Design decisions:
    - VerdictType as string enum for serialization in OTel span attributes.
    - Frozen dataclass for immutability — verdicts are append-only records.
    - Included all fields needed for NIST AI RMF Measure/Manage reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time


class VerdictType(Enum):
    """Enforcement verdict types.

    Ordered by severity for comparison.

    Attributes:
        ALLOW: No taint violations detected. Safe to proceed.
        LOG: Taint detected but policy says log-only. No enforcement.
        WARN: Taint detected, warning emitted. Execution continues.
        REQUIRE_CONFIRMATION: Taint detected, human confirmation required.
        BLOCK: Taint violation confirmed. Tool call rejected.
    """

    ALLOW = "allow"
    LOG = "log"
    WARN = "warn"
    REQUIRE_CONFIRMATION = "require_confirmation"
    BLOCK = "block"

    @property
    def should_block(self) -> bool:
        """Return True if this verdict type blocks execution."""
        return self == VerdictType.BLOCK

    @property
    def should_warn(self) -> bool:
        """Return True if this verdict type requires a warning."""
        return self in (VerdictType.WARN, VerdictType.REQUIRE_CONFIRMATION, VerdictType.BLOCK)

    @property
    def severity_level(self) -> int:
        """Numeric severity for ordering (higher = more severe)."""
        return {
            VerdictType.ALLOW: 0,
            VerdictType.LOG: 1,
            VerdictType.WARN: 2,
            VerdictType.REQUIRE_CONFIRMATION: 3,
            VerdictType.BLOCK: 4,
        }[self]


@dataclass(frozen=True)
class Verdict:
    """A complete enforcement verdict from Erithm.

    Represents the final decision on whether a tool call should be
    allowed, warned, or blocked. Contains full provenance for audit
    logging and compliance reporting.

    Attributes:
        verdict_type: The enforcement decision.
        trace_id: ID of the analyzed trace.
        tool_name: Name of the tool call being evaluated.
        reason: Human-readable explanation of the verdict.
        taint_path: Node IDs showing taint propagation from source to sink.
        taint_label: The taint severity level at the sink.
        confidence: Confidence score in the verdict (0.0–1.0).
        classifier: Which classifier produced the underlying taint label.
        policy_rule: Name of the policy rule that triggered this verdict.
        timestamp: Unix epoch timestamp when the verdict was issued.
        processing_time_ms: Time taken to produce this verdict.
        owasp_ref: OWASP reference for compliance traceability.
        metadata: Additional verdict metadata.
    """

    verdict_type: VerdictType
    trace_id: str = ""
    tool_name: str = ""
    reason: str = ""
    taint_path: tuple[str, ...] = ()
    taint_label: str = ""
    confidence: float = 1.0
    classifier: str = ""
    policy_rule: str = ""
    timestamp: float = field(default_factory=time.time)
    processing_time_ms: float = 0.0
    owasp_ref: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def should_block(self) -> bool:
        """Convenience: does this verdict block the tool call?"""
        return self.verdict_type.should_block

    @property
    def should_warn(self) -> bool:
        """Convenience: does this verdict require a warning?"""
        return self.verdict_type.should_warn

    @property
    def summary(self) -> str:
        """One-line summary suitable for CLI output."""
        icon = {
            VerdictType.ALLOW: "✓",
            VerdictType.LOG: "📝",
            VerdictType.WARN: "⚠",
            VerdictType.REQUIRE_CONFIRMATION: "🔒",
            VerdictType.BLOCK: "✗",
        }[self.verdict_type]
        return f"{icon} [{self.verdict_type.value.upper()}] {self.tool_name}: {self.reason}"


@dataclass(frozen=True)
class AnalysisResult:
    """Complete analysis result for a full trace.

    Aggregates all verdicts from analyzing a single trace, providing
    summary statistics and the overall trace-level verdict.

    Attributes:
        trace_id: ID of the analyzed trace.
        verdicts: All individual verdicts produced during analysis.
        overall_verdict: The most severe verdict across all tool calls.
        total_tool_calls: Number of tool calls in the trace.
        tainted_calls: Number of tool calls that received tainted data.
        violations_found: Number of taint violations (source → sink paths).
        analysis_time_ms: Total analysis time in milliseconds.
    """

    trace_id: str
    verdicts: tuple[Verdict, ...] = ()
    overall_verdict: VerdictType = VerdictType.ALLOW
    total_tool_calls: int = 0
    tainted_calls: int = 0
    violations_found: int = 0
    analysis_time_ms: float = 0.0

    @property
    def is_clean(self) -> bool:
        """Return True if no violations were found."""
        return self.violations_found == 0

    @property
    def has_blocks(self) -> bool:
        """Return True if any tool call was blocked."""
        return any(v.should_block for v in self.verdicts)

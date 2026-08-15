"""
Verdict engine for Erithm.

Takes taint violations from the TaintEngine and policy rules, and
produces enforcement verdicts (block/warn/allow). The verdict engine
is the decision-making layer that translates security analysis into
actionable enforcement.

Design decisions:
    - Each tool call in the trace gets its own verdict, even if no
      violation was found (ALLOW verdict).
    - The most severe verdict across all tool calls determines the
      overall trace verdict.
    - Verdict confidence is derived from the underlying taint analysis.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from erithm.config import ErithmConfig, VerdictMode
from erithm.policy.models import Policy, SinkAction
from erithm.taint.labels import TaintViolation
from erithm.verdict.models import Verdict, VerdictType, AnalysisResult

logger = logging.getLogger(__name__)

# Map SinkAction → VerdictType
_ACTION_TO_VERDICT: dict[SinkAction, VerdictType] = {
    SinkAction.BLOCK: VerdictType.BLOCK,
    SinkAction.WARN: VerdictType.WARN,
    SinkAction.REQUIRE_CONFIRMATION: VerdictType.REQUIRE_CONFIRMATION,
    SinkAction.LOG: VerdictType.LOG,
}


class VerdictEngine:
    """Produces enforcement verdicts from taint violations.

    The verdict engine is the final stage of the Erithm pipeline. It
    translates taint analysis results into actionable enforcement
    decisions, respecting the configured verdict mode.

    Example:
        engine = VerdictEngine(policy=policy, config=config)
        result = engine.evaluate(violations, trace_id="abc123")

        if result.has_blocks:
            print("Blocked tool calls detected!")
    """

    def __init__(
        self,
        policy: Policy,
        config: ErithmConfig | None = None,
    ) -> None:
        """Initialize the verdict engine.

        Args:
            policy: Security policy for enforcement decisions.
            config: Erithm configuration. Uses defaults if None.
        """
        self._policy = policy
        self._config = config or ErithmConfig()

    def evaluate(
        self,
        violations: list[TaintViolation],
        trace_id: str = "",
        total_tool_calls: int = 0,
    ) -> AnalysisResult:
        """Evaluate taint violations and produce an AnalysisResult.

        Args:
            violations: List of taint violations from the TaintEngine.
            trace_id: ID of the analyzed trace.
            total_tool_calls: Total number of tool calls in the trace.

        Returns:
            AnalysisResult with all individual verdicts and summary.
        """
        start_time = time.time()

        verdicts: list[Verdict] = []
        tainted_calls = 0

        for violation in violations:
            verdict = self._violation_to_verdict(violation, trace_id)
            verdicts.append(verdict)
            tainted_calls += 1

        # Determine overall verdict (most severe)
        if verdicts:
            overall = max(
                (v.verdict_type for v in verdicts),
                key=lambda vt: vt.severity_level,
            )
        else:
            overall = VerdictType.ALLOW

        # Apply verdict mode override
        overall = self._apply_mode(overall)

        elapsed = (time.time() - start_time) * 1000

        result = AnalysisResult(
            trace_id=trace_id,
            verdicts=tuple(verdicts),
            overall_verdict=overall,
            total_tool_calls=total_tool_calls,
            tainted_calls=tainted_calls,
            violations_found=len(violations),
            analysis_time_ms=elapsed,
        )

        logger.info(
            "Verdict: %s (violations=%d, tainted=%d/%d, %.1fms)",
            overall.value,
            len(violations),
            tainted_calls,
            total_tool_calls,
            elapsed,
        )

        return result

    def _violation_to_verdict(
        self, violation: TaintViolation, trace_id: str
    ) -> Verdict:
        """Convert a single taint violation to a verdict.

        Args:
            violation: The taint violation.
            trace_id: ID of the trace.

        Returns:
            A Verdict with the enforcement decision.
        """
        # Look up the sink rule for this violation
        sink_rule = self._policy.find_sink_rule(violation.sink_name)

        if sink_rule is not None:
            verdict_type = _ACTION_TO_VERDICT.get(
                sink_rule.action, VerdictType.BLOCK
            )
            policy_rule = sink_rule.name
            owasp_ref = sink_rule.owasp_ref
        else:
            # No specific rule — default to WARN
            verdict_type = VerdictType.WARN
            policy_rule = "default"
            owasp_ref = ""

        # Apply verdict mode override
        verdict_type = self._apply_mode(verdict_type)

        return Verdict(
            verdict_type=verdict_type,
            trace_id=trace_id,
            tool_name=violation.sink_name,
            reason=violation.reason,
            taint_path=violation.taint_path,
            taint_label=violation.taint_label.display_name,
            confidence=violation.confidence,
            classifier=violation.classifier,
            policy_rule=policy_rule,
            owasp_ref=owasp_ref,
        )

    def _apply_mode(self, verdict_type: VerdictType) -> VerdictType:
        """Apply the configured verdict mode to cap enforcement.

        In WARN mode, BLOCK verdicts are downgraded to WARN.
        In LOG mode, all verdicts are downgraded to LOG.

        Args:
            verdict_type: Original verdict type.

        Returns:
            Possibly downgraded verdict type.
        """
        if self._config.verdict_mode == VerdictMode.LOG:
            if verdict_type in (VerdictType.BLOCK, VerdictType.WARN, VerdictType.REQUIRE_CONFIRMATION):
                return VerdictType.LOG

        if self._config.verdict_mode == VerdictMode.WARN:
            if verdict_type == VerdictType.BLOCK:
                return VerdictType.WARN

        return verdict_type

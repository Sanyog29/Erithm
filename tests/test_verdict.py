"""Tests for the verdict engine and audit logger."""

from __future__ import annotations

import pytest

from erithm.config import ErithmConfig, VerdictMode
from erithm.taint.labels import TaintLabel, TaintViolation
from erithm.verdict.engine import VerdictEngine
from erithm.verdict.models import VerdictType, AnalysisResult
from erithm.verdict.audit import AuditLogger


class TestVerdictEngine:
    """Tests for VerdictEngine."""

    def test_no_violations_allow(self, test_policy, test_config):
        """No violations → ALLOW verdict."""
        engine = VerdictEngine(policy=test_policy, config=test_config)
        result = engine.evaluate(violations=[], trace_id="test-001")

        assert result.overall_verdict == VerdictType.ALLOW
        assert result.is_clean
        assert len(result.verdicts) == 0

    def test_violation_produces_block(self, test_policy, test_config):
        """Violation on BLOCK sink → BLOCK verdict."""
        violation = TaintViolation(
            source_node_id="src-001",
            sink_node_id="sink-001",
            sink_name="send_email",
            taint_path=("src-001", "llm-001", "sink-001"),
            taint_label=TaintLabel.INJECTION,
            confidence=0.95,
            reason="Injection detected",
        )

        engine = VerdictEngine(policy=test_policy, config=test_config)
        result = engine.evaluate(violations=[violation], trace_id="test-002")

        assert result.overall_verdict == VerdictType.BLOCK
        assert result.has_blocks
        assert len(result.verdicts) == 1

    def test_warn_mode_downgrades_block(self, test_policy):
        """WARN mode downgrades BLOCK to WARN."""
        config = ErithmConfig(verdict_mode=VerdictMode.WARN)

        violation = TaintViolation(
            source_node_id="src-001",
            sink_node_id="sink-001",
            sink_name="send_email",
            taint_path=("src-001", "sink-001"),
            taint_label=TaintLabel.INJECTION,
        )

        engine = VerdictEngine(policy=test_policy, config=config)
        result = engine.evaluate(violations=[violation], trace_id="test-003")

        assert result.overall_verdict == VerdictType.WARN
        assert not result.has_blocks

    def test_log_mode_downgrades_all(self, test_policy):
        """LOG mode downgrades everything to LOG."""
        config = ErithmConfig(verdict_mode=VerdictMode.LOG)

        violation = TaintViolation(
            source_node_id="src-001",
            sink_node_id="sink-001",
            sink_name="send_email",
            taint_path=("src-001", "sink-001"),
            taint_label=TaintLabel.INJECTION,
        )

        engine = VerdictEngine(policy=test_policy, config=config)
        result = engine.evaluate(violations=[violation], trace_id="test-004")

        assert result.overall_verdict == VerdictType.LOG


class TestAuditLogger:
    """Tests for AuditLogger."""

    def test_log_verdict(self):
        """Single verdict produces audit record."""
        from erithm.verdict.models import Verdict

        audit = AuditLogger()
        verdict = Verdict(
            verdict_type=VerdictType.BLOCK,
            trace_id="test-001",
            tool_name="send_email",
            reason="Injection detected",
            confidence=0.95,
            policy_rule="email",
        )

        record = audit.log_verdict(verdict)
        assert record["event"] == "erithm.verdict"
        assert record["attributes"]["erithm.verdict.type"] == "block"

    def test_audit_trail(self):
        """Audit trail accumulates records."""
        from erithm.verdict.models import Verdict

        audit = AuditLogger()

        for i in range(3):
            audit.log_verdict(Verdict(
                verdict_type=VerdictType.WARN,
                tool_name=f"tool_{i}",
            ))

        trail = audit.get_audit_trail()
        assert len(trail) == 3

    def test_audit_export(self):
        """Audit trail exports as JSON."""
        import json
        from erithm.verdict.models import Verdict

        audit = AuditLogger()
        audit.log_verdict(Verdict(verdict_type=VerdictType.ALLOW))

        export = audit.export_audit_trail()
        parsed = json.loads(export)
        assert len(parsed) == 1

    def test_clear(self):
        """Clear empties the audit trail."""
        from erithm.verdict.models import Verdict

        audit = AuditLogger()
        audit.log_verdict(Verdict(verdict_type=VerdictType.ALLOW))
        audit.clear()

        assert len(audit.get_audit_trail()) == 0


class TestVerdictModel:
    """Tests for Verdict model properties."""

    def test_summary(self):
        from erithm.verdict.models import Verdict

        v = Verdict(
            verdict_type=VerdictType.BLOCK,
            tool_name="send_email",
            reason="Injection found",
        )
        assert "BLOCK" in v.summary
        assert "send_email" in v.summary

    def test_severity_ordering(self):
        """Verdict types have correct severity ordering."""
        assert VerdictType.ALLOW.severity_level < VerdictType.WARN.severity_level
        assert VerdictType.WARN.severity_level < VerdictType.BLOCK.severity_level

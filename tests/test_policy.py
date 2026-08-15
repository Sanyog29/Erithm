"""Tests for policy loading and validation."""

from __future__ import annotations

import pytest
import tempfile
from pathlib import Path

from erithm.policy.loader import PolicyLoader
from erithm.policy.models import Policy, SourceRule, SinkRule, SinkAction


class TestPolicyLoader:
    """Tests for PolicyLoader."""

    def test_load_default(self):
        """Default policy loads successfully."""
        loader = PolicyLoader()
        policy = loader.load_default()

        assert policy.version == "1.0"
        assert len(policy.sources) > 0
        assert len(policy.sinks) > 0

    def test_load_from_yaml(self, tmp_path: Path):
        """Loader parses YAML policy files."""
        yaml_content = """
version: "2.0"
sources:
  - name: "test_source"
    pattern: "*test*"
    taint_level: "external"
sinks:
  - name: "test_sink"
    pattern: "*danger*"
    action: "block"
"""
        file_path = tmp_path / "test_policy.yaml"
        file_path.write_text(yaml_content)

        loader = PolicyLoader()
        policy = loader.load_file(file_path)

        assert policy.version == "2.0"
        assert len(policy.sources) == 1
        assert policy.sources[0].name == "test_source"
        assert len(policy.sinks) == 1
        assert policy.sinks[0].action == SinkAction.BLOCK

    def test_load_missing_file(self):
        """Loader raises on missing file."""
        loader = PolicyLoader()
        with pytest.raises(FileNotFoundError):
            loader.load_file("/nonexistent/policy.yaml")

    def test_load_empty_file(self, tmp_path: Path):
        """Loader raises on empty file."""
        file_path = tmp_path / "empty.yaml"
        file_path.write_text("")

        loader = PolicyLoader()
        with pytest.raises(ValueError, match="Empty"):
            loader.load_file(file_path)

    def test_policy_merge(self):
        """Policy merging works correctly."""
        loader = PolicyLoader()

        base = Policy(
            version="1.0",
            sources=(
                SourceRule(name="src_a", pattern="*a*"),
                SourceRule(name="src_b", pattern="*b*"),
            ),
            sinks=(
                SinkRule(name="sink_x", pattern="*x*"),
            ),
        )

        override = Policy(
            version="2.0",
            sources=(
                SourceRule(name="src_b", pattern="*b_override*"),  # Override
                SourceRule(name="src_c", pattern="*c*"),           # New
            ),
            sinks=(),
        )

        merged = loader.merge(base, override)
        assert merged.version == "2.0"
        assert len(merged.sources) == 3  # a, b(override), c
        assert len(merged.sinks) == 1    # x (from base)


class TestSourceRule:
    """Tests for SourceRule matching."""

    def test_exact_match(self):
        rule = SourceRule(name="test", pattern="web_search")
        assert rule.matches("web_search")
        assert not rule.matches("web_browse")

    def test_glob_match(self):
        rule = SourceRule(name="test", pattern="*search*")
        assert rule.matches("web_search")
        assert rule.matches("google_search_api")
        assert not rule.matches("web_browse")

    def test_case_insensitive(self):
        rule = SourceRule(name="test", pattern="*Search*")
        assert rule.matches("web_search")
        assert rule.matches("WEB_SEARCH")


class TestSinkRule:
    """Tests for SinkRule matching."""

    def test_sink_matching(self):
        rule = SinkRule(name="email", pattern="*email*", action=SinkAction.BLOCK)
        assert rule.matches("send_email")
        assert rule.matches("email_send")
        assert not rule.matches("send_message")

    def test_sink_action(self):
        rule = SinkRule(name="test", pattern="*", action=SinkAction.WARN)
        assert rule.action == SinkAction.WARN

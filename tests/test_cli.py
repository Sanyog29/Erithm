"""Tests for CLI interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from erithm.cli import main


class TestCLI:
    """Tests for the Erithm CLI."""

    def test_version(self):
        """Version command shows version info."""
        runner = CliRunner()
        result = runner.invoke(main, ["--quiet", "version"])
        assert result.exit_code == 0
        assert "v0.1.0" in result.output or "0.1.0" in result.output

    def test_help(self):
        """Help flag shows usage."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Erithm" in result.output

    def test_analyze_missing_file(self):
        """Analyze command fails on missing file."""
        runner = CliRunner()
        result = runner.invoke(main, ["--quiet", "analyze", "/nonexistent/file.json"])
        assert result.exit_code != 0

    def test_policy_validate_default(self):
        """Policy validate works on default policy."""
        default_path = Path(__file__).parent.parent / "erithm" / "policy" / "default_policy.yaml"
        if default_path.exists():
            runner = CliRunner()
            result = runner.invoke(main, ["--quiet", "policy", "validate", str(default_path)])
            assert result.exit_code == 0

    def test_analyze_json_output(self, tmp_path: Path):
        """Analyze command outputs JSON format."""
        # Create a minimal clean trace file
        trace = [
            {
                "traceId": "cli-test-001",
                "spanId": "s1",
                "name": "safe_tool",
                "startTimeUnixNano": "1000000000",
                "endTimeUnixNano": "2000000000",
                "attributes": {
                    "gen_ai.tool.name": "safe_tool",
                    "gen_ai.operation.name": "tool",
                },
                "events": [],
            }
        ]
        file_path = tmp_path / "test_trace.json"
        file_path.write_text(json.dumps(trace))

        runner = CliRunner()
        result = runner.invoke(main, ["--quiet", "analyze", str(file_path), "--output", "json"])
        assert result.exit_code == 0

        output = json.loads(result.output)
        assert "overall_verdict" in output
        assert "violations_found" in output

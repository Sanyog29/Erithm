"""Tests for the ingest pipeline (collector + normalizer)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from erithm.ingest.collector import SpanCollector
from erithm.ingest.normalizer import TraceNormalizer
from erithm.ingest.models import Trace, ToolCall, LLMCall


class TestSpanCollector:
    """Tests for SpanCollector."""

    def test_loopback_enforcement(self):
        """Collector rejects non-loopback endpoints."""
        with pytest.raises(ValueError, match="127.0.0.1"):
            SpanCollector(endpoint="0.0.0.0:4317")

    def test_loopback_accepts_localhost(self):
        """Collector accepts localhost."""
        collector = SpanCollector(endpoint="localhost:4317")
        assert collector.endpoint == "localhost:4317"

    def test_loopback_accepts_127(self):
        """Collector accepts 127.0.0.1."""
        collector = SpanCollector(endpoint="127.0.0.1:4317")
        assert collector.endpoint == "127.0.0.1:4317"

    def test_collect_from_json_file(self, tmp_path: Path):
        """Collector parses JSON array files."""
        spans = [
            {"traceId": "t1", "spanId": "s1", "name": "tool_a"},
            {"traceId": "t1", "spanId": "s2", "name": "tool_b"},
        ]
        file_path = tmp_path / "trace.json"
        file_path.write_text(json.dumps(spans))

        collector = SpanCollector()
        result = collector.collect_from_file(file_path)
        assert len(result) == 2

    def test_collect_from_otlp_format(self):
        """Collector parses OTLP format."""
        data = {
            "resourceSpans": [
                {
                    "resource": {"attributes": []},
                    "scopeSpans": [
                        {
                            "scope": {"name": "test"},
                            "spans": [
                                {"spanId": "s1", "name": "tool_a"},
                                {"spanId": "s2", "name": "tool_b"},
                            ],
                        }
                    ],
                }
            ]
        }
        collector = SpanCollector()
        result = collector.collect_from_dict(data)
        assert len(result) == 2
        assert "_scope_name" in result[0]

    def test_collect_from_jsonl_file(self, tmp_path: Path):
        """Collector parses JSON Lines files."""
        lines = [
            json.dumps({"traceId": "t1", "spanId": "s1"}),
            json.dumps({"traceId": "t1", "spanId": "s2"}),
        ]
        file_path = tmp_path / "trace.jsonl"
        file_path.write_text("\n".join(lines))

        collector = SpanCollector()
        result = collector.collect_from_file(file_path)
        assert len(result) == 2

    def test_file_not_found(self):
        """Collector raises on missing file."""
        collector = SpanCollector()
        with pytest.raises(FileNotFoundError):
            collector.collect_from_file("/nonexistent/file.json")


class TestTraceNormalizer:
    """Tests for TraceNormalizer."""

    def test_normalize_empty(self):
        """Normalizer handles empty input."""
        normalizer = TraceNormalizer()
        trace = normalizer.normalize([])
        assert trace.trace_id == "empty"
        assert len(trace.steps) == 0

    def test_normalize_tool_call(self, sample_raw_spans):
        """Normalizer creates ToolCall from tool span."""
        normalizer = TraceNormalizer()
        trace = normalizer.normalize(sample_raw_spans)

        assert len(trace.steps) >= 1
        tool_calls = trace.tool_calls
        assert len(tool_calls) >= 1
        assert tool_calls[0].name == "web_search"

    def test_normalize_llm_call(self, sample_raw_spans):
        """Normalizer creates LLMCall from LLM span."""
        normalizer = TraceNormalizer()
        trace = normalizer.normalize(sample_raw_spans)

        llm_calls = trace.llm_calls
        assert len(llm_calls) >= 1
        assert llm_calls[0].model == "gpt-4"

    def test_normalize_ordering(self, sample_raw_spans):
        """Steps are ordered by timestamp."""
        normalizer = TraceNormalizer()
        trace = normalizer.normalize(sample_raw_spans)

        for i in range(len(trace.steps) - 1):
            assert trace.steps[i].timestamp <= trace.steps[i + 1].timestamp

    def test_event_content_extraction(self):
        """Normalizer extracts content from events, not attributes."""
        spans = [
            {
                "traceId": "t1",
                "spanId": "s1",
                "name": "my_tool",
                "startTimeUnixNano": "1000000000",
                "endTimeUnixNano": "2000000000",
                "attributes": {
                    "gen_ai.tool.name": "my_tool",
                    "gen_ai.operation.name": "tool",
                },
                "events": [
                    {
                        "name": "gen_ai.content.tool.input",
                        "attributes": {"content": "input_data"},
                    },
                    {
                        "name": "gen_ai.content.tool.output",
                        "attributes": {"content": "output_data"},
                    },
                ],
            }
        ]
        normalizer = TraceNormalizer()
        trace = normalizer.normalize(spans)

        assert len(trace.tool_calls) == 1
        assert trace.tool_calls[0].args == "input_data"
        assert trace.tool_calls[0].result == "output_data"

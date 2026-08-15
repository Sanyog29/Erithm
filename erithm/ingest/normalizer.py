"""
Trace normalizer for Erithm.

Converts raw OTel span dictionaries into structured Trace objects.
Uses the OTel GenAI compatibility layer for attribute name resolution,
ensuring that convention changes don't break the pipeline.

Design decisions:
    - Content stored in span events, not attributes (per PRD Section 7).
    - Spans are sorted by start time for deterministic ordering.
    - Missing attributes are handled gracefully with empty defaults.
    - The normalizer is stateless — each call produces an independent Trace.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from erithm.ingest.models import Trace, TraceStep, ToolCall, LLMCall
from erithm.utils.otel_compat import OTelGenAIMapping as M

logger = logging.getLogger(__name__)


class TraceNormalizer:
    """Converts raw OTel span data into normalized Trace objects.

    Handles the translation from OTel GenAI semantic conventions to
    Erithm's internal data models. All ``gen_ai.*`` attribute names
    are resolved through the OTelGenAIMapping compatibility layer.

    Example:
        normalizer = TraceNormalizer()
        trace = normalizer.normalize(raw_spans)
    """

    def normalize(self, raw_spans: list[dict[str, Any]]) -> Trace:
        """Normalize a list of raw spans into a Trace object.

        Args:
            raw_spans: List of span dictionaries from the SpanCollector.

        Returns:
            A normalized Trace object with ordered steps.
        """
        if not raw_spans:
            return Trace(trace_id="empty", steps=())

        # Sort spans by start time
        sorted_spans = sorted(
            raw_spans,
            key=lambda s: self._get_timestamp(s),
        )

        # Extract trace ID from first span
        trace_id = self._get_trace_id(sorted_spans[0])

        # Convert spans to trace steps
        steps: list[TraceStep] = []
        for idx, span in enumerate(sorted_spans):
            step = self._span_to_step(span, idx)
            if step is not None:
                steps.append(step)

        # Calculate time bounds
        start_time = self._get_timestamp(sorted_spans[0]) if sorted_spans else 0.0
        end_time = self._get_end_timestamp(sorted_spans[-1]) if sorted_spans else 0.0

        # Extract trace-level metadata
        metadata = self._extract_trace_metadata(sorted_spans)

        trace = Trace(
            trace_id=trace_id,
            steps=tuple(steps),
            start_time=start_time,
            end_time=end_time,
            metadata=metadata,
        )

        logger.info(
            "Normalized trace %s: %d steps (%d tool calls, %d LLM calls)",
            trace_id[:8],
            len(steps),
            len(trace.tool_calls),
            len(trace.llm_calls),
        )

        return trace

    def normalize_many(self, raw_spans: list[dict[str, Any]]) -> list[Trace]:
        """Normalize spans into multiple traces, grouped by trace ID.

        Args:
            raw_spans: List of span dictionaries potentially from multiple traces.

        Returns:
            List of Trace objects, one per unique trace ID.
        """
        # Group spans by trace ID
        traces_map: dict[str, list[dict[str, Any]]] = {}
        for span in raw_spans:
            tid = self._get_trace_id(span)
            if tid not in traces_map:
                traces_map[tid] = []
            traces_map[tid].append(span)

        # Normalize each group
        return [self.normalize(spans) for spans in traces_map.values()]

    def _span_to_step(self, span: dict[str, Any], index: int) -> TraceStep | None:
        """Convert a single span to a TraceStep.

        Determines the step type from span attributes and delegates
        to the appropriate converter.

        Args:
            span: Raw span dictionary.
            index: Step index in the trace.

        Returns:
            A ToolCall or LLMCall, or None if the span type is unrecognized.
        """
        attrs = self._get_attributes(span)
        operation = attrs.get(M.OPERATION_NAME, "")

        # Check for tool call span
        tool_name = attrs.get(M.TOOL_NAME, "")
        if tool_name or operation == "tool":
            return self._to_tool_call(span, attrs, index)

        # Check for LLM call span
        model = attrs.get(M.LLM_MODEL, "")
        if model or operation in ("chat", "completion", "llm"):
            return self._to_llm_call(span, attrs, index)

        # Check span name for hints
        span_name = span.get("name", "").lower()
        if "tool" in span_name:
            return self._to_tool_call(span, attrs, index)
        if any(kw in span_name for kw in ("llm", "chat", "completion", "generate")):
            return self._to_llm_call(span, attrs, index)

        logger.debug("Skipping unrecognized span: %s", span.get("name", "unknown"))
        return None

    def _to_tool_call(
        self, span: dict[str, Any], attrs: dict[str, Any], index: int
    ) -> ToolCall:
        """Convert a span to a ToolCall.

        Args:
            span: Raw span dictionary.
            attrs: Extracted span attributes.
            index: Step index.

        Returns:
            A ToolCall data model.
        """
        # Extract content from events (not attributes — per PRD Section 7)
        tool_input = self._get_event_content(span, M.EVENT_TOOL_INPUT)
        tool_output = self._get_event_content(span, M.EVENT_TOOL_OUTPUT)

        # Fallback: check attributes if events are empty (for compatibility)
        if not tool_input:
            tool_input = attrs.get("tool.input", attrs.get("tool.args", ""))
        if not tool_output:
            tool_output = attrs.get("tool.output", attrs.get("tool.result", ""))

        return ToolCall(
            name=attrs.get(M.TOOL_NAME, span.get("name", f"tool_{index}")),
            args=str(tool_input) if tool_input else "",
            result=str(tool_output) if tool_output else "",
            timestamp=self._get_timestamp(span),
            span_id=self._get_span_id(span),
            trace_id=self._get_trace_id(span),
            parent_span_id=span.get("parentSpanId", ""),
            duration_ms=self._get_duration_ms(span),
            metadata=self._safe_metadata(attrs),
        )

    def _to_llm_call(
        self, span: dict[str, Any], attrs: dict[str, Any], index: int
    ) -> LLMCall:
        """Convert a span to an LLMCall.

        Args:
            span: Raw span dictionary.
            attrs: Extracted span attributes.
            index: Step index.

        Returns:
            An LLMCall data model.
        """
        # Extract content from events
        prompt = self._get_event_content(span, M.EVENT_PROMPT)
        completion = self._get_event_content(span, M.EVENT_COMPLETION)

        return LLMCall(
            model=attrs.get(M.LLM_MODEL, attrs.get(M.LLM_RESPONSE_MODEL, "")),
            messages=str(prompt) if prompt else "",
            completion=str(completion) if completion else "",
            prompt_tokens=int(attrs.get(M.PROMPT_TOKENS, 0)),
            completion_tokens=int(attrs.get(M.COMPLETION_TOKENS, 0)),
            timestamp=self._get_timestamp(span),
            span_id=self._get_span_id(span),
            trace_id=self._get_trace_id(span),
            parent_span_id=span.get("parentSpanId", ""),
            duration_ms=self._get_duration_ms(span),
            metadata=self._safe_metadata(attrs),
        )

    def _get_attributes(self, span: dict[str, Any]) -> dict[str, Any]:
        """Extract attributes from a span, handling both flat and OTLP formats.

        Args:
            span: Raw span dictionary.

        Returns:
            Flat dictionary of attribute key-value pairs.
        """
        attrs = span.get("attributes", {})

        # OTLP format: attributes is a list of {key, value} objects
        if isinstance(attrs, list):
            result = {}
            for attr in attrs:
                key = attr.get("key", "")
                value = attr.get("value", {})
                if isinstance(value, dict):
                    from erithm.ingest.collector import SpanCollector
                    result[key] = SpanCollector._extract_otel_value(value)
                else:
                    result[key] = value
            return result

        return attrs

    def _get_event_content(self, span: dict[str, Any], event_name: str) -> str:
        """Extract content from a span event by name.

        Content in OTel GenAI conventions should be stored in span events,
        not attributes. This method searches the span's events list for
        a matching event and returns its content.

        Args:
            span: Raw span dictionary.
            event_name: Name of the event to find.

        Returns:
            Event content string, or empty string if not found.
        """
        events = span.get("events", [])
        for event in events:
            name = event.get("name", "")
            if name == event_name:
                # Content may be in event body or attributes
                body = event.get("body", "")
                if body:
                    return str(body)
                event_attrs = event.get("attributes", {})
                if isinstance(event_attrs, dict):
                    return event_attrs.get("content", event_attrs.get("value", ""))
        return ""

    @staticmethod
    def _get_timestamp(span: dict[str, Any]) -> float:
        """Extract start timestamp from a span.

        Args:
            span: Raw span dictionary.

        Returns:
            Unix epoch timestamp as float.
        """
        ts = span.get("startTimeUnixNano", span.get("start_time", 0))
        if isinstance(ts, str):
            ts = int(ts)
        # Convert nanoseconds to seconds if needed
        if ts > 1e18:
            return ts / 1e9
        if ts > 1e15:
            return ts / 1e6
        return float(ts)

    @staticmethod
    def _get_end_timestamp(span: dict[str, Any]) -> float:
        """Extract end timestamp from a span.

        Args:
            span: Raw span dictionary.

        Returns:
            Unix epoch timestamp as float.
        """
        ts = span.get("endTimeUnixNano", span.get("end_time", 0))
        if isinstance(ts, str):
            ts = int(ts)
        if ts > 1e18:
            return ts / 1e9
        if ts > 1e15:
            return ts / 1e6
        return float(ts)

    @staticmethod
    def _get_duration_ms(span: dict[str, Any]) -> float:
        """Calculate span duration in milliseconds.

        Args:
            span: Raw span dictionary.

        Returns:
            Duration in milliseconds.
        """
        start = span.get("startTimeUnixNano", 0)
        end = span.get("endTimeUnixNano", 0)
        if isinstance(start, str):
            start = int(start)
        if isinstance(end, str):
            end = int(end)
        if start and end:
            return (end - start) / 1e6  # ns to ms
        return 0.0

    @staticmethod
    def _get_span_id(span: dict[str, Any]) -> str:
        """Extract span ID from a span.

        Args:
            span: Raw span dictionary.

        Returns:
            Span ID string.
        """
        return str(span.get("spanId", span.get("span_id", "")))

    @staticmethod
    def _get_trace_id(span: dict[str, Any]) -> str:
        """Extract trace ID from a span.

        Args:
            span: Raw span dictionary.

        Returns:
            Trace ID string.
        """
        return str(span.get("traceId", span.get("trace_id", "unknown")))

    @staticmethod
    def _safe_metadata(attrs: dict[str, Any]) -> dict[str, str]:
        """Convert attributes to string-only metadata, excluding content.

        Filters out large content fields and converts all values to strings
        for safe storage in metadata.

        Args:
            attrs: Span attribute dictionary.

        Returns:
            Filtered and stringified metadata dictionary.
        """
        skip_keys = {"tool.input", "tool.output", "tool.args", "tool.result"}
        return {
            k: str(v)
            for k, v in attrs.items()
            if k not in skip_keys and len(str(v)) < 500
        }

    def _extract_trace_metadata(self, spans: list[dict]) -> dict[str, str]:
        """Extract trace-level metadata from spans.

        Collects resource attributes and other trace-level information
        from the first span in the trace.

        Args:
            spans: Sorted list of span dictionaries.

        Returns:
            Trace-level metadata dictionary.
        """
        metadata: dict[str, str] = {}

        if not spans:
            return metadata

        # Extract resource attributes from first span
        first = spans[0]
        resource_attrs = first.get("_resource_attributes", {})
        if isinstance(resource_attrs, dict):
            for k, v in resource_attrs.items():
                metadata[f"resource.{k}"] = str(v)

        # Extract scope name
        scope_name = first.get("_scope_name", "")
        if scope_name:
            metadata["scope.name"] = scope_name

        return metadata


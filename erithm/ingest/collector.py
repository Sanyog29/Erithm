"""
OTel span collector for Erithm.

Receives OpenTelemetry spans from agent runtimes via two modes:
    1. **Offline mode**: Reads exported trace files (JSON/OTLP format).
    2. **Real-time mode**: Listens for spans on a gRPC endpoint.

The collector normalizes raw span data into a list of dictionaries
that the TraceNormalizer then converts into Trace objects.

Security:
    - Real-time listener binds to 127.0.0.1 only — never 0.0.0.0.
    - No raw span content is logged at INFO level or below.
    - File paths are resolved and validated before reading.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class SpanCollector:
    """Collects OTel spans from files or gRPC endpoints.

    The collector is the entry point of the Erithm pipeline. It handles
    both offline (file-based) and real-time (gRPC) span collection,
    producing a list of raw span dictionaries for normalization.

    Attributes:
        endpoint: gRPC endpoint for real-time mode (default: 127.0.0.1:4317).

    Example:
        collector = SpanCollector()
        spans = collector.collect_from_file("trace.json")
    """

    def __init__(self, endpoint: str = "127.0.0.1:4317") -> None:
        """Initialize the span collector.

        Args:
            endpoint: gRPC endpoint address for real-time collection.
                MUST be a loopback address (127.0.0.1). Never use 0.0.0.0.

        Raises:
            ValueError: If endpoint does not bind to loopback address.
        """
        # Security: enforce loopback-only binding
        if not endpoint.startswith("127.0.0.1") and not endpoint.startswith("localhost"):
            raise ValueError(
                f"Security: SpanCollector endpoint must bind to 127.0.0.1 or "
                f"localhost, got '{endpoint}'. Binding to 0.0.0.0 is forbidden."
            )
        self._endpoint = endpoint
        self._spans: list[dict[str, Any]] = []
        logger.info("SpanCollector initialized (endpoint=%s)", endpoint)

    @property
    def endpoint(self) -> str:
        """Return the configured gRPC endpoint."""
        return self._endpoint

    def collect_from_file(self, file_path: str | Path) -> list[dict[str, Any]]:
        """Collect spans from an exported trace file.

        Supports JSON format (OTel JSON exporter output). The file is
        expected to contain either:
            - A JSON array of span objects
            - A JSON object with a 'resourceSpans' key (OTLP format)
            - A JSON Lines file (one span per line)

        Args:
            file_path: Path to the trace file.

        Returns:
            List of raw span dictionaries.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file format is not recognized.
        """
        path = Path(file_path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"Trace file not found: {path}")

        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")

        logger.info("Collecting spans from file: %s", path.name)

        content = path.read_text(encoding="utf-8")

        # Try parsing as JSON
        try:
            data = json.loads(content)
            return self._parse_json_data(data)
        except json.JSONDecodeError:
            pass

        # Try parsing as JSON Lines
        spans = self._parse_jsonl(content)
        if spans:
            return spans

        raise ValueError(
            f"Unrecognized trace file format: {path.name}. "
            "Expected JSON array, OTLP JSON, or JSON Lines."
        )

    def collect_from_dict(self, data: dict[str, Any] | list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Collect spans from an in-memory data structure.

        Useful for testing and programmatic integration where spans
        are already available as Python objects.

        Args:
            data: Either a list of span dicts or an OTLP-format dict.

        Returns:
            List of raw span dictionaries.
        """
        if isinstance(data, list):
            return data
        return self._parse_json_data(data)

    def _parse_json_data(self, data: Any) -> list[dict[str, Any]]:
        """Parse a JSON data structure into span dictionaries.

        Handles three formats:
            1. Direct list of spans
            2. OTLP format with resourceSpans
            3. Single span object

        Args:
            data: Parsed JSON data.

        Returns:
            List of span dictionaries.
        """
        if isinstance(data, list):
            logger.debug("Parsed %d spans from JSON array", len(data))
            return data

        if isinstance(data, dict):
            # OTLP format: { "resourceSpans": [ ... ] }
            if "resourceSpans" in data:
                return self._parse_otlp_format(data)

            # Erithm trace format: { "trace_id": ..., "spans": [...] }
            if "spans" in data:
                spans = data["spans"]
                logger.debug("Parsed %d spans from 'spans' key", len(spans))
                return spans

            # Single span
            logger.debug("Parsed 1 span from single object")
            return [data]

        raise ValueError(f"Unexpected JSON data type: {type(data).__name__}")

    def _parse_otlp_format(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse OTLP export format into flat span list.

        OTLP format nests spans under:
            resourceSpans → scopeSpans → spans

        This method flattens the hierarchy, preserving resource and scope
        attributes on each span.

        Args:
            data: OTLP-format JSON dictionary.

        Returns:
            Flattened list of span dictionaries with resource metadata.
        """
        spans: list[dict[str, Any]] = []

        for resource_span in data.get("resourceSpans", []):
            resource_attrs = {}
            resource = resource_span.get("resource", {})
            for attr in resource.get("attributes", []):
                key = attr.get("key", "")
                value = attr.get("value", {})
                resource_attrs[key] = self._extract_otel_value(value)

            for scope_span in resource_span.get("scopeSpans", []):
                scope = scope_span.get("scope", {})
                scope_name = scope.get("name", "")

                for span in scope_span.get("spans", []):
                    # Attach resource and scope metadata
                    span["_resource_attributes"] = resource_attrs
                    span["_scope_name"] = scope_name
                    spans.append(span)

        logger.debug("Parsed %d spans from OTLP format", len(spans))
        return spans

    def _parse_jsonl(self, content: str) -> list[dict[str, Any]]:
        """Parse JSON Lines format (one span per line).

        Args:
            content: File content string.

        Returns:
            List of span dictionaries, or empty list if parsing fails.
        """
        spans: list[dict[str, Any]] = []
        for line_num, line in enumerate(content.strip().split("\n"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                span = json.loads(line)
                if isinstance(span, dict):
                    spans.append(span)
            except json.JSONDecodeError:
                logger.warning("Skipping invalid JSON on line %d", line_num)
                continue

        if spans:
            logger.debug("Parsed %d spans from JSON Lines format", len(spans))
        return spans

    @staticmethod
    def _extract_otel_value(value: dict[str, Any]) -> Any:
        """Extract a scalar value from an OTel attribute value wrapper.

        OTel JSON format wraps values in typed containers:
            {"stringValue": "..."}, {"intValue": "..."}, etc.

        Args:
            value: OTel attribute value dictionary.

        Returns:
            Extracted Python value.
        """
        if "stringValue" in value:
            return value["stringValue"]
        if "intValue" in value:
            return int(value["intValue"])
        if "doubleValue" in value:
            return float(value["doubleValue"])
        if "boolValue" in value:
            return bool(value["boolValue"])
        if "arrayValue" in value:
            return [
                SpanCollector._extract_otel_value(v)
                for v in value["arrayValue"].get("values", [])
            ]
        return str(value)

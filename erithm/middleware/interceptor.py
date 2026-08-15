"""
Erithm middleware interceptor — drop-in agent integration layer.

Orchestrates the full Erithm pipeline (ingest → graph → taint → verdict)
as a single call. Designed for easy integration with any agent runtime.

Usage:
    from erithm import ErithmInterceptor

    interceptor = ErithmInterceptor()

    # Offline analysis
    result = interceptor.analyze_file("trace.json")

    # Programmatic analysis
    result = interceptor.analyze_trace(trace_data)

    if result.has_blocks:
        raise SecurityViolation(result)
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from erithm.config import ErithmConfig, load_config
from erithm.ingest.collector import SpanCollector
from erithm.ingest.normalizer import TraceNormalizer
from erithm.graph.builder import GraphBuilder
from erithm.policy.loader import PolicyLoader
from erithm.taint.engine import TaintEngine
from erithm.verdict.engine import VerdictEngine
from erithm.verdict.models import AnalysisResult
from erithm.verdict.audit import AuditLogger

logger = logging.getLogger(__name__)


class ErithmInterceptor:
    """Drop-in middleware that orchestrates the full Erithm pipeline.

    The interceptor is the primary integration point for agent runtimes.
    It manages the lifecycle of all pipeline components and provides
    simple methods for analyzing traces.

    Components:
        - SpanCollector: Receives/reads OTel spans.
        - TraceNormalizer: Converts raw spans to Trace objects.
        - GraphBuilder: Builds data-flow graphs from traces.
        - TaintEngine: Propagates taint and classifies injection.
        - VerdictEngine: Produces enforcement decisions.
        - AuditLogger: Logs all verdicts for compliance.

    Example:
        interceptor = ErithmInterceptor()
        result = interceptor.analyze_file("trace.json")

        for verdict in result.verdicts:
            print(verdict.summary)
    """

    def __init__(
        self,
        config: ErithmConfig | None = None,
        config_path: Path | None = None,
    ) -> None:
        """Initialize the interceptor with all pipeline components.

        Args:
            config: Erithm configuration. If None, loads from config
                file and environment variables.
            config_path: Optional path to erithm.yaml config file.
        """
        self._config = config or load_config(config_path)

        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self._config.log_level, logging.INFO),
            format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Initialize pipeline components
        self._collector = SpanCollector(
            endpoint=self._config.otel.endpoint,
        )
        self._normalizer = TraceNormalizer()
        self._graph_builder = GraphBuilder()

        # Load policy
        policy_loader = PolicyLoader()
        try:
            self._policy = policy_loader.load_file(self._config.policy_path)
        except (FileNotFoundError, ValueError):
            logger.warning("Policy load failed — using defaults")
            self._policy = policy_loader.load_default()

        self._taint_engine = TaintEngine(
            policy=self._policy,
            config=self._config,
        )
        self._verdict_engine = VerdictEngine(
            policy=self._policy,
            config=self._config,
        )
        self._audit = AuditLogger()

        logger.info("Erithm interceptor initialized (mode=%s)", self._config.verdict_mode.value)

    def analyze_file(self, file_path: str | Path) -> AnalysisResult:
        """Analyze a trace from an exported file.

        Runs the full pipeline: collect → normalize → graph → taint → verdict.

        Args:
            file_path: Path to the trace file (JSON/JSONL/OTLP format).

        Returns:
            AnalysisResult with all verdicts and summary.
        """
        start_time = time.time()

        # Stage 1: Collect
        raw_spans = self._collector.collect_from_file(file_path)

        # Stage 2: Normalize
        trace = self._normalizer.normalize(raw_spans)

        # Stage 3: Build graph
        graph = self._graph_builder.build(trace)

        # Stage 4: Taint analysis
        violations = self._taint_engine.analyze(graph, trace)

        # Stage 5: Verdict
        result = self._verdict_engine.evaluate(
            violations=violations,
            trace_id=trace.trace_id,
            total_tool_calls=len(trace.tool_calls),
        )

        # Stage 6: Audit
        self._audit.log_result(result)

        elapsed = (time.time() - start_time) * 1000
        logger.info("Full analysis complete in %.1fms", elapsed)

        return result

    def analyze_trace(
        self, trace_data: dict[str, Any] | list[dict[str, Any]]
    ) -> AnalysisResult:
        """Analyze a trace from in-memory data.

        Args:
            trace_data: Raw span data (list of spans or OTLP format).

        Returns:
            AnalysisResult with all verdicts and summary.
        """
        start_time = time.time()

        # Collect from dict
        raw_spans = self._collector.collect_from_dict(trace_data)

        # Normalize
        trace = self._normalizer.normalize(raw_spans)

        # Build graph
        graph = self._graph_builder.build(trace)

        # Taint analysis
        violations = self._taint_engine.analyze(graph, trace)

        # Verdict
        result = self._verdict_engine.evaluate(
            violations=violations,
            trace_id=trace.trace_id,
            total_tool_calls=len(trace.tool_calls),
        )

        # Audit
        self._audit.log_result(result)

        elapsed = (time.time() - start_time) * 1000
        logger.info("Full analysis complete in %.1fms", elapsed)

        return result

    def get_audit_trail(self) -> list[dict[str, Any]]:
        """Return all audit records from this session.

        Returns:
            List of structured audit record dictionaries.
        """
        return self._audit.get_audit_trail()

    @property
    def config(self) -> ErithmConfig:
        """Return the current configuration."""
        return self._config

    @property
    def policy(self):
        """Return the loaded policy."""
        return self._policy

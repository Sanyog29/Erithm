"""
Taint propagation engine — the core contribution of Erithm.

Implements information-flow-based taint analysis on the data-flow graph.
The engine:
    1. Marks source nodes as tainted (per policy rules).
    2. Propagates taint labels through graph edges using BFS.
    3. Checks if tainted data reaches any privileged sink node.
    4. Classifies ambiguous content using heuristic or LM-judge.
    5. Produces TaintViolation objects for each flagged source→sink path.

Propagation semantics:
    - DATA_FLOW edges: taint propagates at full confidence.
    - IMPLICIT_FLOW edges: taint propagates at edge confidence × label confidence.
    - CONTROL_FLOW edges: taint does NOT propagate (ordering only).
    - Join points: conservative merge (most-tainted label wins).
    - Max depth limit prevents infinite loops in cyclic graphs.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any

import networkx as nx

from erithm.config import ClassifierMode, ErithmConfig
from erithm.graph.models import NodeType, EdgeType, GraphNode, GraphEdge
from erithm.ingest.models import Trace, ToolCall
from erithm.policy.models import Policy
from erithm.taint.classifier import BaseClassifier, HeuristicClassifier
from erithm.taint.labels import TaintLabel, TaintInfo, TaintViolation
from erithm.taint.lm_judge import LMJudgeClassifier
from erithm.utils.redactor import ContentRedactor

logger = logging.getLogger(__name__)


class TaintEngine:
    """Core taint propagation engine for Erithm.

    Orchestrates taint analysis on a data-flow graph:
        1. Source marking — apply taint labels to source nodes per policy.
        2. Content classification — analyze tool output content for injection.
        3. BFS propagation — propagate taint through data-flow edges.
        4. Sink checking — detect when tainted data reaches privileged sinks.
        5. Violation reporting — produce TaintViolation objects.

    Example:
        engine = TaintEngine(policy=policy, config=config)
        violations = engine.analyze(graph, trace)

        for v in violations:
            print(f"VIOLATION: {v.sink_name} (confidence={v.confidence})")
    """

    def __init__(
        self,
        policy: Policy,
        config: ErithmConfig | None = None,
        classifier: BaseClassifier | None = None,
    ) -> None:
        """Initialize the taint engine.

        Args:
            policy: Security policy defining sources and sinks.
            config: Erithm configuration. Uses defaults if None.
            classifier: Taint classifier. Auto-selected based on config if None.
        """
        self._policy = policy
        self._config = config or ErithmConfig()
        self._redactor = ContentRedactor(enabled=self._config.redact_content)

        # Select classifier based on configuration
        if classifier is not None:
            self._classifier = classifier
        elif self._config.classifier_mode == ClassifierMode.HEURISTIC:
            self._classifier = HeuristicClassifier()
        else:
            # AUTO or LM_JUDGE — use LM-judge with heuristic fallback
            self._classifier = LMJudgeClassifier(
                config=self._config.lm_judge,
                heuristic_fallback=HeuristicClassifier(),
            )

        # Taint state: node_id → TaintInfo
        self._taint_map: dict[str, TaintInfo] = {}

    def analyze(
        self, graph: nx.DiGraph, trace: Trace
    ) -> list[TaintViolation]:
        """Run full taint analysis on a data-flow graph.

        This is the main entry point for the taint engine. It runs the
        complete analysis pipeline and returns all detected violations.

        Args:
            graph: Data-flow graph from GraphBuilder.
            trace: Source trace for content access.

        Returns:
            List of TaintViolation objects, one per flagged path.
        """
        start_time = time.time()

        # Reset state
        self._taint_map.clear()

        if graph.number_of_nodes() == 0:
            return []

        # Phase 1: Mark source nodes
        sources_marked = self._mark_sources(graph, trace)
        logger.info("Marked %d source nodes", sources_marked)

        # Phase 2: Classify content at source nodes
        self._classify_sources(graph, trace)

        # Phase 3: Propagate taint through the graph
        self._propagate(graph)

        # Phase 4: Check sinks and produce violations
        violations = self._check_sinks(graph, trace)

        elapsed = (time.time() - start_time) * 1000
        logger.info(
            "Taint analysis complete: %d violations found (%.1fms)",
            len(violations),
            elapsed,
        )

        return violations

    def _mark_sources(self, graph: nx.DiGraph, trace: Trace) -> int:
        """Mark source nodes with initial taint labels per policy.

        Args:
            graph: Data-flow graph.
            trace: Source trace.

        Returns:
            Number of nodes marked as sources.
        """
        count = 0

        for node_id, data in graph.nodes(data=True):
            node_data: GraphNode = data.get("node_data")
            if node_data is None:
                continue

            if node_data.node_type != NodeType.TOOL_CALL:
                continue

            # Check if this tool is a source
            source_rule = self._policy.find_source_rule(node_data.name)
            if source_rule is not None:
                taint_info = TaintInfo(
                    label=source_rule.taint_label,
                    source_node_id=node_id,
                    propagation_path=(node_id,),
                    confidence=1.0,
                    classifier="policy",
                    reason=f"Source rule '{source_rule.name}' matched tool '{node_data.name}'",
                )
                self._taint_map[node_id] = taint_info
                count += 1

        return count

    def _classify_sources(self, graph: nx.DiGraph, trace: Trace) -> None:
        """Run content classification on tainted source nodes.

        Checks the actual content of tool outputs at source nodes to
        determine if they contain injection patterns. This may upgrade
        the taint label from EXTERNAL to INJECTION.

        Args:
            graph: Data-flow graph.
            trace: Source trace for content access.
        """
        # Build a lookup from node_id to trace step
        step_lookup = self._build_step_lookup(graph, trace)

        for node_id, taint_info in list(self._taint_map.items()):
            step = step_lookup.get(node_id)
            if step is None or not isinstance(step, ToolCall):
                continue

            # Classify the tool's result content
            content = step.result
            if not content:
                continue

            context = {"tool_name": step.name, "node_id": node_id}
            result = self._classifier.classify(content, context)

            if result.is_injection:
                # Upgrade taint label to INJECTION
                upgraded = TaintInfo(
                    label=TaintLabel.INJECTION,
                    source_node_id=node_id,
                    propagation_path=(node_id,),
                    confidence=result.confidence,
                    classifier=result.classifier,
                    reason=result.reason,
                )
                self._taint_map[node_id] = upgraded
                logger.info(
                    "Content classification upgraded node %s to INJECTION "
                    "(classifier=%s, confidence=%.2f)",
                    node_id[:16],
                    result.classifier,
                    result.confidence,
                )

    def _propagate(self, graph: nx.DiGraph) -> None:
        """Propagate taint labels through the data-flow graph using BFS.

        Taint flows through DATA_FLOW and IMPLICIT_FLOW edges only.
        CONTROL_FLOW edges are ignored (ordering, not data dependency).
        At join points, the conservative merge selects the most-tainted label.

        Args:
            graph: Data-flow graph.
        """
        max_depth = self._policy.settings.max_propagation_depth

        # BFS from all tainted source nodes simultaneously
        queue: deque[tuple[str, int]] = deque()  # (node_id, depth)
        visited: set[str] = set()

        for node_id in list(self._taint_map.keys()):
            queue.append((node_id, 0))
            visited.add(node_id)

        while queue:
            current_id, depth = queue.popleft()

            if depth >= max_depth:
                logger.warning(
                    "Max propagation depth (%d) reached at node %s",
                    max_depth,
                    current_id[:16],
                )
                continue

            current_taint = self._taint_map.get(current_id)
            if current_taint is None:
                continue

            # Propagate to successors
            for _, target_id, edge_data_dict in graph.out_edges(current_id, data=True):
                edge_data: GraphEdge = edge_data_dict.get("edge_data")
                if edge_data is None:
                    continue

                # Skip control-flow edges — they don't carry data
                if edge_data.edge_type == EdgeType.CONTROL_FLOW:
                    continue

                # Calculate propagated taint
                propagated = self._propagate_through_edge(
                    current_taint, edge_data, target_id
                )

                # Merge with existing taint at target
                existing = self._taint_map.get(target_id)
                if existing is not None:
                    merged = existing.merge(propagated)
                    if merged is existing:
                        # No change — don't re-process
                        continue
                    self._taint_map[target_id] = merged
                else:
                    self._taint_map[target_id] = propagated

                # Add to queue for further propagation
                if target_id not in visited:
                    visited.add(target_id)
                    queue.append((target_id, depth + 1))

    def _propagate_through_edge(
        self, source_taint: TaintInfo, edge: GraphEdge, target_id: str
    ) -> TaintInfo:
        """Calculate the taint info after propagation through an edge.

        Args:
            source_taint: Taint info at the source node.
            edge: The edge being traversed.
            target_id: ID of the target node.

        Returns:
            New TaintInfo for the target node.
        """
        # Confidence degrades through implicit flows
        if edge.edge_type == EdgeType.IMPLICIT_FLOW:
            confidence = source_taint.confidence * edge.confidence
        else:
            confidence = source_taint.confidence

        return TaintInfo(
            label=source_taint.label,
            source_node_id=source_taint.source_node_id,
            propagation_path=source_taint.propagation_path + (target_id,),
            confidence=confidence,
            classifier=source_taint.classifier,
            reason=source_taint.reason,
        )

    def _check_sinks(
        self, graph: nx.DiGraph, trace: Trace
    ) -> list[TaintViolation]:
        """Check if tainted data reached any privileged sink nodes.

        Args:
            graph: Data-flow graph.
            trace: Source trace.

        Returns:
            List of TaintViolation objects for each flagged path.
        """
        violations: list[TaintViolation] = []
        step_lookup = self._build_step_lookup(graph, trace)

        for node_id, data in graph.nodes(data=True):
            node_data: GraphNode = data.get("node_data")
            if node_data is None:
                continue

            if node_data.node_type != NodeType.TOOL_CALL:
                continue

            # Check if this tool is a sink
            sink_rule = self._policy.find_sink_rule(node_data.name)
            if sink_rule is None:
                continue

            # Check if this node has taint
            taint_info = self._taint_map.get(node_id)
            if taint_info is None or not taint_info.is_tainted:
                continue

            # Check if taint level meets the sink's minimum threshold
            if taint_info.label < sink_rule.min_taint_label:
                continue

            # Create content snippet for the violation
            step = step_lookup.get(node_id)
            snippet = ""
            if step is not None and isinstance(step, ToolCall):
                snippet = self._redactor.create_snippet(step.args, max_length=200)

            violation = TaintViolation(
                source_node_id=taint_info.source_node_id,
                sink_node_id=node_id,
                sink_name=node_data.name,
                taint_path=taint_info.propagation_path,
                taint_label=taint_info.label,
                confidence=taint_info.confidence,
                classifier=taint_info.classifier,
                reason=taint_info.reason,
                content_snippet=snippet,
            )
            violations.append(violation)

            logger.warning(
                "TAINT VIOLATION: %s → %s (label=%s, confidence=%.2f, "
                "path_length=%d)",
                taint_info.source_node_id[:16],
                node_data.name,
                taint_info.label.display_name,
                taint_info.confidence,
                violation.path_length,
            )

        return violations

    def _build_step_lookup(
        self, graph: nx.DiGraph, trace: Trace
    ) -> dict[str, Any]:
        """Build a mapping from node_id to trace step.

        Args:
            graph: Data-flow graph.
            trace: Source trace.

        Returns:
            Dict mapping node IDs to TraceStep objects.
        """
        lookup: dict[str, Any] = {}

        for node_id, data in graph.nodes(data=True):
            node_data: GraphNode = data.get("node_data")
            if node_data is None:
                continue

            idx = node_data.step_index
            if 0 <= idx < len(trace.steps):
                lookup[node_id] = trace.steps[idx]

        return lookup

    def get_taint_map(self) -> dict[str, TaintInfo]:
        """Return the current taint state (for inspection/debugging).

        Returns:
            Copy of the taint map (node_id → TaintInfo).
        """
        return dict(self._taint_map)

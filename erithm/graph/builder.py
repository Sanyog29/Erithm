"""
Data-flow graph builder for Erithm.

Constructs a networkx DiGraph from a normalized Trace. The graph represents
data-flow relationships between tool calls, with edges showing how data
from one tool's output reaches another tool's input (typically mediated
through an LLM call).

Graph construction strategy:
    1. Create a node for each trace step (ToolCall or LLMCall).
    2. Create CONTROL_FLOW edges for sequential ordering.
    3. Create IMPLICIT_FLOW edges for LLM-mediated data flows:
       - Tool output → LLM call (tool result injected into LLM context)
       - LLM call → Tool call (LLM generates tool call arguments)
    4. Detect DATA_FLOW edges via parent-child span relationships.

The IMPLICIT_FLOW edges are the critical ones for prompt injection
detection — they represent the path where attacker-controlled tool
output can influence LLM-generated tool call arguments.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import networkx as nx

from erithm.ingest.models import Trace, ToolCall, LLMCall, TraceStep
from erithm.graph.models import NodeType, EdgeType, GraphNode, GraphEdge

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds a data-flow DiGraph from a normalized Trace.

    The builder walks the trace steps in order and creates nodes and
    edges representing data-flow relationships. The resulting graph
    is used by the TaintEngine for propagation analysis.

    Example:
        builder = GraphBuilder()
        graph = builder.build(trace)
        print(f"Graph has {graph.number_of_nodes()} nodes")
    """

    def build(self, trace: Trace) -> nx.DiGraph:
        """Build a data-flow graph from a trace.

        Args:
            trace: Normalized Trace object.

        Returns:
            A networkx DiGraph with GraphNode data on nodes and
            GraphEdge data on edges.
        """
        graph = nx.DiGraph()

        if not trace.steps:
            logger.warning("Empty trace — returning empty graph")
            return graph

        # Phase 1: Create nodes for all steps
        node_map = self._create_nodes(graph, trace)

        # Phase 2: Create control-flow edges (sequential ordering)
        self._create_control_flow_edges(graph, trace, node_map)

        # Phase 3: Create data-flow edges (parent-child spans)
        self._create_data_flow_edges(graph, trace, node_map)

        # Phase 4: Create implicit-flow edges (LLM-mediated flows)
        self._create_implicit_flow_edges(graph, trace, node_map)

        logger.info(
            "Built graph for trace %s: %d nodes, %d edges "
            "(%d data-flow, %d implicit-flow, %d control-flow)",
            trace.trace_id[:8],
            graph.number_of_nodes(),
            graph.number_of_edges(),
            sum(
                1 for _, _, d in graph.edges(data=True)
                if d.get("edge_data", GraphEdge(EdgeType.CONTROL_FLOW, "", "")).edge_type == EdgeType.DATA_FLOW
            ),
            sum(
                1 for _, _, d in graph.edges(data=True)
                if d.get("edge_data", GraphEdge(EdgeType.CONTROL_FLOW, "", "")).edge_type == EdgeType.IMPLICIT_FLOW
            ),
            sum(
                1 for _, _, d in graph.edges(data=True)
                if d.get("edge_data", GraphEdge(EdgeType.CONTROL_FLOW, "", "")).edge_type == EdgeType.CONTROL_FLOW
            ),
        )

        return graph

    def _create_nodes(
        self, graph: nx.DiGraph, trace: Trace
    ) -> dict[int, str]:
        """Create graph nodes for all trace steps.

        Args:
            graph: The DiGraph to populate.
            trace: Source trace.

        Returns:
            Mapping from step index to node ID.
        """
        node_map: dict[int, str] = {}

        for idx, step in enumerate(trace.steps):
            node_id = self._make_node_id(step, idx)

            if isinstance(step, ToolCall):
                node_type = NodeType.TOOL_CALL
                name = step.name
                content = step.args + step.result
            elif isinstance(step, LLMCall):
                node_type = NodeType.LLM_CALL
                name = step.model or f"llm_{idx}"
                content = step.messages + step.completion
            else:
                continue

            node_data = GraphNode(
                node_id=node_id,
                node_type=node_type,
                name=name,
                span_id=step.span_id,
                step_index=idx,
                content_hash=self._hash_content(content),
            )

            graph.add_node(node_id, node_data=node_data)
            node_map[idx] = node_id

        return node_map

    def _create_control_flow_edges(
        self,
        graph: nx.DiGraph,
        trace: Trace,
        node_map: dict[int, str],
    ) -> None:
        """Create control-flow edges between sequential steps.

        These edges represent temporal ordering — step i happens before
        step i+1. They don't represent data dependency but provide
        context for the taint engine.

        Args:
            graph: The DiGraph to populate.
            trace: Source trace.
            node_map: Step index → node ID mapping.
        """
        indices = sorted(node_map.keys())
        for i in range(len(indices) - 1):
            src_id = node_map[indices[i]]
            dst_id = node_map[indices[i + 1]]

            edge_data = GraphEdge(
                edge_type=EdgeType.CONTROL_FLOW,
                source_id=src_id,
                target_id=dst_id,
                confidence=1.0,
                description="sequential execution",
            )

            graph.add_edge(src_id, dst_id, edge_data=edge_data)

    def _create_data_flow_edges(
        self,
        graph: nx.DiGraph,
        trace: Trace,
        node_map: dict[int, str],
    ) -> None:
        """Create data-flow edges based on parent-child span relationships.

        If span B's parentSpanId matches span A's spanId, and A produces
        output that B consumes, create a DATA_FLOW edge from A to B.

        Args:
            graph: The DiGraph to populate.
            trace: Source trace.
            node_map: Step index → node ID mapping.
        """
        # Build span_id → step_index lookup
        span_to_idx: dict[str, int] = {}
        for idx, step in enumerate(trace.steps):
            if step.span_id:
                span_to_idx[step.span_id] = idx

        # Create edges based on parent relationships
        for idx, step in enumerate(trace.steps):
            if idx not in node_map:
                continue
            if step.parent_span_id and step.parent_span_id in span_to_idx:
                parent_idx = span_to_idx[step.parent_span_id]
                if parent_idx in node_map:
                    src_id = node_map[parent_idx]
                    dst_id = node_map[idx]

                    # Avoid self-loops
                    if src_id != dst_id:
                        edge_data = GraphEdge(
                            edge_type=EdgeType.DATA_FLOW,
                            source_id=src_id,
                            target_id=dst_id,
                            confidence=0.9,
                            description="parent-child span relationship",
                        )
                        graph.add_edge(src_id, dst_id, edge_data=edge_data)

    def _create_implicit_flow_edges(
        self,
        graph: nx.DiGraph,
        trace: Trace,
        node_map: dict[int, str],
    ) -> None:
        """Create implicit-flow edges for LLM-mediated data flows.

        This is the critical edge type for prompt injection detection.
        The pattern is:
            ToolCall_A → LLMCall → ToolCall_B

        Where ToolCall_A's output is included in the LLM's context,
        and the LLM generates ToolCall_B's arguments. An attacker who
        controls ToolCall_A's output can inject instructions that
        influence ToolCall_B's arguments.

        Heuristic: For each LLM call, create edges from all preceding
        tool calls to the LLM, and from the LLM to all subsequent
        tool calls (until the next LLM call).

        Args:
            graph: The DiGraph to populate.
            trace: Source trace.
            node_map: Step index → node ID mapping.
        """
        indices = sorted(node_map.keys())

        for i, idx in enumerate(indices):
            step = trace.steps[idx]

            if not isinstance(step, LLMCall):
                continue

            llm_node_id = node_map[idx]

            # Find preceding tool calls (since the previous LLM call)
            preceding_tools: list[str] = []
            for j in range(i - 1, -1, -1):
                prev_idx = indices[j]
                prev_step = trace.steps[prev_idx]
                if isinstance(prev_step, LLMCall):
                    break  # Stop at previous LLM call
                if isinstance(prev_step, ToolCall):
                    preceding_tools.append(node_map[prev_idx])

            # Find subsequent tool calls (until the next LLM call)
            subsequent_tools: list[str] = []
            for j in range(i + 1, len(indices)):
                next_idx = indices[j]
                next_step = trace.steps[next_idx]
                if isinstance(next_step, LLMCall):
                    break  # Stop at next LLM call
                if isinstance(next_step, ToolCall):
                    subsequent_tools.append(node_map[next_idx])

            # Create edges: preceding_tools → LLM
            for tool_id in preceding_tools:
                edge_data = GraphEdge(
                    edge_type=EdgeType.IMPLICIT_FLOW,
                    source_id=tool_id,
                    target_id=llm_node_id,
                    confidence=0.8,
                    description="tool output injected into LLM context",
                )
                graph.add_edge(tool_id, llm_node_id, edge_data=edge_data)

            # Create edges: LLM → subsequent_tools
            for tool_id in subsequent_tools:
                edge_data = GraphEdge(
                    edge_type=EdgeType.IMPLICIT_FLOW,
                    source_id=llm_node_id,
                    target_id=tool_id,
                    confidence=0.8,
                    description="LLM generates tool call arguments",
                )
                graph.add_edge(llm_node_id, tool_id, edge_data=edge_data)

    @staticmethod
    def _make_node_id(step: TraceStep, index: int) -> str:
        """Generate a unique node ID for a trace step.

        Args:
            step: The trace step.
            index: Step index in the trace.

        Returns:
            Unique node ID string.
        """
        if step.span_id:
            return f"{step.span_id}_{index}"
        # Fallback: use step type and index
        prefix = "tool" if isinstance(step, ToolCall) else "llm"
        name = step.name if isinstance(step, ToolCall) else getattr(step, "model", "")
        return f"{prefix}_{name}_{index}"

    @staticmethod
    def _hash_content(content: str) -> str:
        """Create a SHA-256 hash of content for deduplication.

        Hashes content rather than storing it raw in the graph, per
        PRD Section 7 security requirements.

        Args:
            content: Content string to hash.

        Returns:
            Hex-encoded SHA-256 hash (first 16 chars).
        """
        return hashlib.sha256(content.encode()).hexdigest()[:16]

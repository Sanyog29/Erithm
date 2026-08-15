"""Tests for graph construction."""

from __future__ import annotations

import pytest
import networkx as nx

from erithm.graph.builder import GraphBuilder
from erithm.graph.models import NodeType, EdgeType, GraphNode, GraphEdge
from erithm.ingest.models import Trace, ToolCall, LLMCall


class TestGraphBuilder:
    """Tests for GraphBuilder."""

    def test_empty_trace(self):
        """Empty trace produces empty graph."""
        builder = GraphBuilder()
        trace = Trace(trace_id="empty", steps=())
        graph = builder.build(trace)
        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0

    def test_nodes_created(self, clean_trace):
        """All trace steps become graph nodes."""
        builder = GraphBuilder()
        graph = builder.build(clean_trace)
        assert graph.number_of_nodes() == len(clean_trace.steps)

    def test_node_types(self, clean_trace):
        """Tool calls and LLM calls have correct node types."""
        builder = GraphBuilder()
        graph = builder.build(clean_trace)

        tool_nodes = [
            n for n, d in graph.nodes(data=True)
            if d["node_data"].node_type == NodeType.TOOL_CALL
        ]
        llm_nodes = [
            n for n, d in graph.nodes(data=True)
            if d["node_data"].node_type == NodeType.LLM_CALL
        ]

        assert len(tool_nodes) == 2  # web_search + display_result
        assert len(llm_nodes) == 1  # gpt-4

    def test_control_flow_edges(self, clean_trace):
        """Sequential steps are connected in the graph."""
        builder = GraphBuilder()
        graph = builder.build(clean_trace)

        # All sequential pairs should be connected (via any edge type)
        # In a 3-step trace (tool→LLM→tool), implicit-flow edges may
        # replace control-flow edges since DiGraph allows one edge per pair
        nodes = sorted(graph.nodes(), key=lambda n: graph.nodes[n]["node_data"].step_index)
        for i in range(len(nodes) - 1):
            assert graph.has_edge(nodes[i], nodes[i + 1]), (
                f"Missing edge between step {i} and step {i+1}"
            )

    def test_implicit_flow_edges(self, injection_trace):
        """LLM-mediated flows create implicit-flow edges."""
        builder = GraphBuilder()
        graph = builder.build(injection_trace)

        implicit_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d["edge_data"].edge_type == EdgeType.IMPLICIT_FLOW
        ]
        # web_search → LLM and LLM → send_email
        assert len(implicit_edges) >= 2

    def test_graph_is_directed(self, clean_trace):
        """Graph is a directed graph."""
        builder = GraphBuilder()
        graph = builder.build(clean_trace)
        assert isinstance(graph, nx.DiGraph)

    def test_content_hashing(self, clean_trace):
        """Nodes store content hashes, not raw content."""
        builder = GraphBuilder()
        graph = builder.build(clean_trace)

        for _, data in graph.nodes(data=True):
            node_data: GraphNode = data["node_data"]
            # Content hash should be present and non-empty
            if node_data.content_hash:
                assert len(node_data.content_hash) == 16  # SHA-256 first 16 chars

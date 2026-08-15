"""
Graph node and edge type definitions for the Erithm data-flow graph.

These models define the structure of the networkx DiGraph that represents
data-flow relationships between tool calls in an agent trace. Nodes
represent tool calls, LLM calls, or data values. Edges represent data
flow from one node to another.

Design decisions:
    - NodeType and EdgeType are string enums for networkx attribute storage.
    - GraphNode and GraphEdge are frozen dataclasses used as networkx
      node/edge data containers.
    - Node IDs are derived from span_id + step index for uniqueness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class NodeType(Enum):
    """Classification of nodes in the data-flow graph.

    Attributes:
        TOOL_CALL: A tool invocation node. May be a source or sink.
        LLM_CALL: An LLM inference node. Acts as a data transformer —
            tool outputs flow in, tool call arguments flow out.
        DATA_VALUE: A standalone data value node. Used for explicit
            intermediate values in the flow.
    """

    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"
    DATA_VALUE = "data_value"


class EdgeType(Enum):
    """Classification of edges in the data-flow graph.

    Attributes:
        DATA_FLOW: Direct data dependency — output of source node feeds
            into input of target node.
        CONTROL_FLOW: Sequential execution ordering without direct data
            dependency. Used for temporal context in taint analysis.
        IMPLICIT_FLOW: Data flows indirectly through an LLM call — the
            LLM reads a tool output and generates arguments for the next
            tool call. This is the critical edge type for prompt injection.
    """

    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    IMPLICIT_FLOW = "implicit_flow"


@dataclass(frozen=True)
class GraphNode:
    """Data container for a node in the data-flow graph.

    Stored as the ``data`` attribute on a networkx node.

    Attributes:
        node_id: Unique identifier (derived from span_id or step index).
        node_type: Classification of this node.
        name: Human-readable name (tool name, model name, or value label).
        span_id: Original OTel span ID for provenance.
        step_index: Position in the original trace ordering.
        content_hash: SHA-256 hash of the node's content (args/result).
            Used for deduplication without storing raw content in the graph.
        metadata: Additional node attributes.
    """

    node_id: str
    node_type: NodeType
    name: str
    span_id: str = ""
    step_index: int = 0
    content_hash: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """Data container for an edge in the data-flow graph.

    Stored as the ``data`` attribute on a networkx edge.

    Attributes:
        edge_type: Classification of this edge.
        source_id: Node ID of the data source.
        target_id: Node ID of the data target.
        confidence: Confidence score (0.0–1.0) that this data flow exists.
            1.0 for explicit flows, lower for implicit LLM-mediated flows.
        description: Human-readable description of the data flow.
    """

    edge_type: EdgeType
    source_id: str
    target_id: str
    confidence: float = 1.0
    description: str = ""

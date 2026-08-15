"""
Graph module — Stage 2 of the Erithm pipeline.

Constructs networkx DiGraphs from normalized Trace objects. The graph
represents data-flow relationships between tool calls, enabling taint
propagation analysis.
"""

from erithm.graph.builder import GraphBuilder
from erithm.graph.models import NodeType, EdgeType, GraphNode, GraphEdge

__all__ = [
    "GraphBuilder",
    "NodeType",
    "EdgeType",
    "GraphNode",
    "GraphEdge",
]

"""
Ingest module — Stage 1 of the Erithm pipeline.

Receives OpenTelemetry GenAI spans from agent runtimes, normalizes them
into structured Trace objects for downstream graph construction and
taint analysis.
"""

from erithm.ingest.collector import SpanCollector
from erithm.ingest.normalizer import TraceNormalizer
from erithm.ingest.models import Trace, TraceStep, ToolCall, LLMCall

__all__ = [
    "SpanCollector",
    "TraceNormalizer",
    "Trace",
    "TraceStep",
    "ToolCall",
    "LLMCall",
]

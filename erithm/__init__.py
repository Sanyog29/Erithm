"""
Erithm — Taint-analysis firewall for LLM tool-calling agents.

Erithm is a framework-agnostic security middleware that ingests OpenTelemetry
GenAI spans from any LLM agent runtime, constructs data-flow graphs of tool
calls, propagates taint labels through the graph, and issues block/warn/allow
verdicts when attacker-controlled content reaches privileged sinks.

Architecture:
    Agent Runtime → [OTel Spans] → Ingest → Graph → Taint → Verdict → Agent

Typical usage::

    from erithm import ErithmInterceptor

    interceptor = ErithmInterceptor()
    verdict = interceptor.analyze_trace(trace_data)

    if verdict.should_block:
        raise SecurityViolation(verdict.reason)
"""

__version__ = "0.1.0"
__author__ = "Sanyog-Tripathi"

from erithm.verdict.models import Verdict, VerdictType
from erithm.middleware.interceptor import ErithmInterceptor
from erithm.middleware.decorator import with_erithm
from erithm.config import ErithmConfig, ClassifierMode, VerdictMode

__all__ = [
    "ErithmInterceptor",
    "with_erithm",
    "ErithmConfig",
    "ClassifierMode",
    "VerdictMode",
    "__version__",
]

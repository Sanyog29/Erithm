"""
Utilities module — shared helpers for the Erithm pipeline.

Provides the OTel GenAI attribute compatibility layer and content
redaction for secure span event logging.
"""

from erithm.utils.otel_compat import OTelGenAIMapping
from erithm.utils.redactor import ContentRedactor

__all__ = [
    "OTelGenAIMapping",
    "ContentRedactor",
]

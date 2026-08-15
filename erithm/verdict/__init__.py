"""
Verdict module — Stage 4 of the Erithm pipeline.

Produces enforcement decisions (block/warn/allow) based on taint violations
and policy rules. Logs every verdict as an OTel span for audit trail.
"""

from erithm.verdict.engine import VerdictEngine
from erithm.verdict.models import Verdict, VerdictType
from erithm.verdict.audit import AuditLogger

__all__ = [
    "VerdictEngine",
    "Verdict",
    "VerdictType",
    "AuditLogger",
]

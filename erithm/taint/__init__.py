"""
Taint module — Stage 3 of the Erithm pipeline (core contribution).

Implements taint propagation and classification. Marks untrusted sources,
propagates taint labels through the data-flow graph, and classifies
ambiguous cases using heuristic patterns or an LM-as-judge.

Note: Imports are lazy to avoid circular dependency with policy.models.
    policy.models → taint.labels (ok, labels has no further erithm imports)
    taint.engine → policy.models (ok at runtime, but not at __init__ time)
"""

from erithm.taint.labels import TaintLabel, TaintInfo, TaintViolation

__all__ = [
    "TaintEngine",
    "HeuristicClassifier",
    "LMJudgeClassifier",
    "BaseClassifier",
    "TaintLabel",
    "TaintInfo",
    "TaintViolation",
]


def __getattr__(name: str):
    """Lazy imports for modules that have circular dependencies."""
    if name == "TaintEngine":
        from erithm.taint.engine import TaintEngine
        return TaintEngine
    if name in ("HeuristicClassifier", "BaseClassifier"):
        from erithm.taint import classifier
        return getattr(classifier, name)
    if name == "LMJudgeClassifier":
        from erithm.taint.lm_judge import LMJudgeClassifier
        return LMJudgeClassifier
    raise AttributeError(f"module 'erithm.taint' has no attribute {name!r}")

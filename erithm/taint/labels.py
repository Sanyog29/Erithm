"""
Taint label definitions and violation data structures.

Defines the taint lattice used by the propagation engine. Labels form
a partial order from CLEAN (least restrictive) to INJECTION (most
restrictive). The engine always propagates the most-tainted label at
join points (conservative merge).

Lattice:
    CLEAN < EXTERNAL < USER_INPUT < INJECTION

    - CLEAN: Data originates from a trusted, internal source.
    - EXTERNAL: Data originates from an external source (web search,
      retrieved docs, API responses) but no injection detected.
    - USER_INPUT: Data originates from direct user input. May be
      intentional or unintentional injection vector.
    - INJECTION: Data contains detected prompt injection patterns.
      Highest severity — triggers block/warn on any privileged sink.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class TaintLabel(IntEnum):
    """Taint severity levels forming a lattice.

    IntEnum so that ``max()`` naturally returns the most-tainted label
    at graph join points.

    Attributes:
        CLEAN: Trusted internal data. No taint.
        EXTERNAL: External source data. Low severity.
        USER_INPUT: User-provided data. Medium severity.
        INJECTION: Detected prompt injection. Highest severity.
    """

    CLEAN = 0
    EXTERNAL = 1
    USER_INPUT = 2
    INJECTION = 3

    @property
    def is_tainted(self) -> bool:
        """Return True if this label represents any level of taint."""
        return self >= TaintLabel.EXTERNAL

    @property
    def display_name(self) -> str:
        """Human-readable display name for CLI output."""
        return {
            TaintLabel.CLEAN: "Clean",
            TaintLabel.EXTERNAL: "External Source",
            TaintLabel.USER_INPUT: "User Input",
            TaintLabel.INJECTION: "Prompt Injection",
        }[self]

    @property
    def severity(self) -> str:
        """Severity string for audit logging."""
        return {
            TaintLabel.CLEAN: "none",
            TaintLabel.EXTERNAL: "low",
            TaintLabel.USER_INPUT: "medium",
            TaintLabel.INJECTION: "critical",
        }[self]


@dataclass(frozen=True)
class TaintInfo:
    """Taint metadata attached to a graph node.

    Tracks both the current taint label and the full provenance chain
    showing how the taint propagated through the graph.

    Attributes:
        label: Current taint severity level.
        source_node_id: ID of the original source node that introduced taint.
        propagation_path: Ordered list of node IDs showing the taint path.
        confidence: Confidence score (0.0–1.0) in the taint classification.
        classifier: Which classifier produced this label ('heuristic' or 'lm_judge').
        reason: Human-readable explanation of why this label was assigned.
    """

    label: TaintLabel
    source_node_id: str = ""
    propagation_path: tuple[str, ...] = ()
    confidence: float = 1.0
    classifier: str = "heuristic"
    reason: str = ""

    @property
    def is_tainted(self) -> bool:
        """Return True if this info represents any taint."""
        return self.label.is_tainted

    def merge(self, other: TaintInfo) -> TaintInfo:
        """Merge two taint infos at a join point (conservative: most-tainted wins).

        Args:
            other: Another TaintInfo to merge with.

        Returns:
            The TaintInfo with the higher taint label. If equal, the one
            with higher confidence is preferred.
        """
        if other.label > self.label:
            return other
        if other.label == self.label and other.confidence > self.confidence:
            return other
        return self


@dataclass(frozen=True)
class TaintViolation:
    """Represents a taint violation — tainted data reaching a privileged sink.

    This is the primary output of the taint engine, passed to the verdict
    engine for enforcement decisions.

    Attributes:
        source_node_id: ID of the node that introduced taint.
        sink_node_id: ID of the privileged sink node that received taint.
        sink_name: Human-readable name of the sink tool.
        taint_path: Full propagation path from source to sink.
        taint_label: The taint label at the sink.
        confidence: Confidence in the violation detection.
        classifier: Which classifier detected the injection.
        reason: Human-readable explanation of the violation.
        content_snippet: Abbreviated content that triggered the violation.
            Truncated to 200 chars max — never contains full payload.
    """

    source_node_id: str
    sink_node_id: str
    sink_name: str
    taint_path: tuple[str, ...]
    taint_label: TaintLabel
    confidence: float = 1.0
    classifier: str = "heuristic"
    reason: str = ""
    content_snippet: str = ""

    @property
    def severity(self) -> str:
        """Severity string for the violation."""
        return self.taint_label.severity

    @property
    def path_length(self) -> int:
        """Number of hops from source to sink."""
        return len(self.taint_path)

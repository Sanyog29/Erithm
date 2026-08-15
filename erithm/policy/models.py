"""
Policy rule data models.

Defines the structured representation of Erithm security policies.
Policies specify which tool calls are untrusted sources, which are
privileged sinks, and what enforcement action to take when tainted
data reaches a sink.

Design decisions:
    - SinkAction enum for type-safe enforcement configuration.
    - Pattern matching via fnmatch-style globs for tool name matching,
      providing flexibility without regex complexity.
    - TaintLevel string mapping to TaintLabel for policy-to-engine bridge.
    - Global policy settings for cross-cutting configuration.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from erithm.taint.labels import TaintLabel


class SinkAction(Enum):
    """Enforcement action when tainted data reaches a privileged sink.

    Attributes:
        BLOCK: Reject the tool call entirely. Strictest enforcement.
        WARN: Allow the call but emit a warning. For shadow-mode rollout.
        REQUIRE_CONFIRMATION: Pause and require human confirmation.
        LOG: Silent audit log only. For monitoring without enforcement.
    """

    BLOCK = "block"
    WARN = "warn"
    REQUIRE_CONFIRMATION = "require_confirmation"
    LOG = "log"


@dataclass(frozen=True)
class SourceRule:
    """Defines an untrusted data source in the policy.

    Tool calls matching this rule will have their outputs marked with
    the specified taint level before propagation.

    Attributes:
        name: Human-readable rule name (e.g., 'web_search').
        pattern: Glob pattern to match against tool names (e.g., 'search_*').
        taint_level: Taint label to apply to matching tool outputs.
        description: Human-readable description for audit logs.
    """

    name: str
    pattern: str
    taint_level: str = "external"
    description: str = ""

    def matches(self, tool_name: str) -> bool:
        """Check if a tool name matches this source rule's pattern.

        Args:
            tool_name: The tool name to check.

        Returns:
            True if the tool name matches the glob pattern.
        """
        return fnmatch.fnmatch(tool_name.lower(), self.pattern.lower())

    @property
    def taint_label(self) -> TaintLabel:
        """Convert the string taint level to a TaintLabel enum value."""
        mapping = {
            "external": TaintLabel.EXTERNAL,
            "user_input": TaintLabel.USER_INPUT,
            "injection": TaintLabel.INJECTION,
            "clean": TaintLabel.CLEAN,
        }
        return mapping.get(self.taint_level.lower(), TaintLabel.EXTERNAL)


@dataclass(frozen=True)
class SinkRule:
    """Defines a privileged sink in the policy.

    Tool calls matching this rule are considered security-sensitive.
    If tainted data reaches a matching tool call, the configured
    enforcement action is triggered.

    Attributes:
        name: Human-readable rule name (e.g., 'email').
        pattern: Glob pattern to match against tool names.
        action: Enforcement action when tainted data reaches this sink.
        min_taint_level: Minimum taint level required to trigger enforcement.
            Defaults to 'external' (any taint triggers).
        description: Human-readable description for audit logs.
        owasp_ref: OWASP reference ID for compliance traceability.
    """

    name: str
    pattern: str
    action: SinkAction = SinkAction.BLOCK
    min_taint_level: str = "external"
    description: str = ""
    owasp_ref: str = ""

    def matches(self, tool_name: str) -> bool:
        """Check if a tool name matches this sink rule's pattern.

        Args:
            tool_name: The tool name to check.

        Returns:
            True if the tool name matches the glob pattern.
        """
        return fnmatch.fnmatch(tool_name.lower(), self.pattern.lower())

    @property
    def min_taint_label(self) -> TaintLabel:
        """Convert the minimum taint level string to a TaintLabel."""
        mapping = {
            "external": TaintLabel.EXTERNAL,
            "user_input": TaintLabel.USER_INPUT,
            "injection": TaintLabel.INJECTION,
            "clean": TaintLabel.CLEAN,
        }
        return mapping.get(self.min_taint_level.lower(), TaintLabel.EXTERNAL)


@dataclass(frozen=True)
class PolicySettings:
    """Global policy settings that apply across all rules.

    Attributes:
        default_source_taint: Default taint level for unmatched external sources.
        enable_implicit_flow_tracking: Whether to track taint through LLM calls.
        max_propagation_depth: Maximum graph depth for taint propagation.
            Prevents infinite loops in cyclic graphs.
        classifier_confidence_threshold: Minimum confidence for LM-judge
            classifications to be accepted (below this, falls back to heuristic).
    """

    default_source_taint: str = "external"
    enable_implicit_flow_tracking: bool = True
    max_propagation_depth: int = 50
    classifier_confidence_threshold: float = 0.7


@dataclass(frozen=True)
class Policy:
    """Complete Erithm security policy.

    Combines source rules, sink rules, and global settings into a single
    policy object used by the taint engine and verdict engine.

    Attributes:
        version: Policy schema version for forward compatibility.
        sources: List of untrusted source rules.
        sinks: List of privileged sink rules.
        settings: Global policy settings.
        metadata: Policy metadata (author, last modified, etc.).
    """

    version: str = "1.0"
    sources: tuple[SourceRule, ...] = ()
    sinks: tuple[SinkRule, ...] = ()
    settings: PolicySettings = field(default_factory=PolicySettings)
    metadata: dict[str, str] = field(default_factory=dict)

    def find_source_rule(self, tool_name: str) -> Optional[SourceRule]:
        """Find the first source rule matching a tool name.

        Args:
            tool_name: The tool name to match.

        Returns:
            The matching SourceRule, or None if no rule matches.
        """
        for rule in self.sources:
            if rule.matches(tool_name):
                return rule
        return None

    def find_sink_rule(self, tool_name: str) -> Optional[SinkRule]:
        """Find the first sink rule matching a tool name.

        Args:
            tool_name: The tool name to match.

        Returns:
            The matching SinkRule, or None if no rule matches.
        """
        for rule in self.sinks:
            if rule.matches(tool_name):
                return rule
        return None

    def is_source(self, tool_name: str) -> bool:
        """Check if a tool name is classified as an untrusted source."""
        return self.find_source_rule(tool_name) is not None

    def is_sink(self, tool_name: str) -> bool:
        """Check if a tool name is classified as a privileged sink."""
        return self.find_sink_rule(tool_name) is not None

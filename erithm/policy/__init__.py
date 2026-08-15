"""
Policy module — YAML-based security policy DSL.

Defines source/sink rules that control which tool calls are treated as
untrusted data sources and which are treated as privileged sinks.
Policies are loaded from YAML files with strict schema validation.
"""

from erithm.policy.models import Policy, SourceRule, SinkRule, SinkAction

__all__ = [
    "PolicyLoader",
    "Policy",
    "SourceRule",
    "SinkRule",
    "SinkAction",
]


def __getattr__(name: str):
    """Lazy import PolicyLoader to avoid circular dependency."""
    if name == "PolicyLoader":
        from erithm.policy.loader import PolicyLoader
        return PolicyLoader
    raise AttributeError(f"module 'erithm.policy' has no attribute {name!r}")


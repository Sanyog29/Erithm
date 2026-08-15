"""
OTel GenAI semantic convention compatibility layer.

The OpenTelemetry GenAI semantic conventions are pre-1.0 (as of 2026).
Attribute names may shift between releases. This module isolates all
``gen_ai.*`` attribute string references behind a thin mapping layer
so that convention changes require updates in exactly one place.

This directly addresses the risk identified in PRD Section 10:
    "OTel GenAI conventions are pre-1.0 — attribute names may shift.
    Isolate gen_ai.* strings behind a thin mapping layer, don't scatter
    them through the codebase."

Usage:
    from erithm.utils.otel_compat import OTelGenAIMapping as M

    tool_name = span.attributes.get(M.TOOL_NAME)
    model = span.attributes.get(M.LLM_MODEL)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _OTelGenAIMapping:
    """Centralized mapping of OTel GenAI semantic convention attribute names.

    All ``gen_ai.*`` attribute references in the Erithm codebase MUST go
    through this mapping. When conventions update, change values here only.

    Attributes are grouped by category: system, LLM, tool, token usage,
    and Erithm-specific custom attributes.
    """

    # --- System-level attributes ---
    SYSTEM: str = "gen_ai.system"
    OPERATION_NAME: str = "gen_ai.operation.name"

    # --- LLM request/response attributes ---
    LLM_MODEL: str = "gen_ai.request.model"
    LLM_TEMPERATURE: str = "gen_ai.request.temperature"
    LLM_MAX_TOKENS: str = "gen_ai.request.max_tokens"
    LLM_TOP_P: str = "gen_ai.request.top_p"
    LLM_RESPONSE_MODEL: str = "gen_ai.response.model"
    LLM_RESPONSE_ID: str = "gen_ai.response.id"
    LLM_FINISH_REASON: str = "gen_ai.response.finish_reasons"

    # --- Tool attributes ---
    TOOL_NAME: str = "gen_ai.tool.name"
    TOOL_CALL_ID: str = "gen_ai.tool.call.id"
    TOOL_DESCRIPTION: str = "gen_ai.tool.description"

    # --- Token usage attributes ---
    PROMPT_TOKENS: str = "gen_ai.usage.input_tokens"
    COMPLETION_TOKENS: str = "gen_ai.usage.output_tokens"

    # --- Span event names (content goes in events, not attributes) ---
    EVENT_PROMPT: str = "gen_ai.content.prompt"
    EVENT_COMPLETION: str = "gen_ai.content.completion"
    EVENT_TOOL_INPUT: str = "gen_ai.content.tool.input"
    EVENT_TOOL_OUTPUT: str = "gen_ai.content.tool.output"

    # --- Erithm custom attributes (namespaced to avoid conflicts) ---
    ERITHM_VERDICT: str = "erithm.verdict"
    ERITHM_VERDICT_TYPE: str = "erithm.verdict.type"
    ERITHM_TAINT_LABEL: str = "erithm.taint.label"
    ERITHM_TAINT_SOURCE: str = "erithm.taint.source"
    ERITHM_TAINT_PATH: str = "erithm.taint.path"
    ERITHM_POLICY_RULE: str = "erithm.policy.rule"
    ERITHM_CONFIDENCE: str = "erithm.confidence"
    ERITHM_CLASSIFIER: str = "erithm.classifier"

    # --- Span kind values ---
    SPAN_KIND_LLM: str = "llm"
    SPAN_KIND_TOOL: str = "tool"
    SPAN_KIND_AGENT: str = "agent"

    def get_all_gen_ai_attributes(self) -> list[str]:
        """Return all gen_ai.* attribute names for validation/filtering.

        Returns:
            List of all attribute name strings that start with 'gen_ai.'.
        """
        return [
            v for k, v in self.__dict__.items()
            if isinstance(v, str) and v.startswith("gen_ai.")
        ]

    def get_all_erithm_attributes(self) -> list[str]:
        """Return all erithm.* attribute names.

        Returns:
            List of all Erithm-namespaced attribute name strings.
        """
        return [
            v for k, v in self.__dict__.items()
            if isinstance(v, str) and v.startswith("erithm.")
        ]


# Singleton instance — import this, not the class
OTelGenAIMapping = _OTelGenAIMapping()

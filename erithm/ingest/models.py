"""
Data models for the Erithm ingest pipeline.

These models represent the normalized intermediate representation of an
agent's execution trace. Raw OTel spans are converted into these structures
by the TraceNormalizer before being passed to the graph builder.

Design decisions:
    - Frozen dataclasses for immutability — traces should never be mutated
      after construction.
    - Timestamps as floats (Unix epoch) for sorting and comparison efficiency.
    - Tool call args/results stored as strings, not dicts — the taint engine
      operates on string content, and deserialization is the normalizer's job.
    - Optional taint_label field on ToolCall for forward compatibility with
      pre-tagged traces.

Security:
    - Content fields (args, result, messages) may contain attacker-controlled
      data. They are never logged at INFO level or below.
    - span_id fields are opaque identifiers, safe to log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class StepType(Enum):
    """Discriminator for trace step types.

    Attributes:
        TOOL_CALL: A tool invocation by the agent (e.g., search, send_email).
        LLM_CALL: An LLM inference call (prompt → completion).
    """

    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"


@dataclass(frozen=True)
class ToolCall:
    """Represents a single tool invocation within an agent trace.

    Attributes:
        name: The tool's registered name (e.g., 'web_search', 'send_email').
        args: Serialized arguments passed to the tool (JSON string).
        result: Serialized result returned by the tool (JSON string).
        timestamp: Unix epoch timestamp when the call was made.
        span_id: OTel span identifier for provenance tracking.
        trace_id: Parent trace identifier.
        parent_span_id: Parent span ID for hierarchical trace reconstruction.
        duration_ms: Call duration in milliseconds.
        taint_label: Optional pre-assigned taint label from source policy.
        metadata: Additional key-value metadata from span attributes.
    """

    name: str
    args: str = ""
    result: str = ""
    timestamp: float = 0.0
    span_id: str = ""
    trace_id: str = ""
    parent_span_id: str = ""
    duration_ms: float = 0.0
    taint_label: Optional[str] = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def step_type(self) -> StepType:
        """Return the step type discriminator."""
        return StepType.TOOL_CALL


@dataclass(frozen=True)
class LLMCall:
    """Represents a single LLM inference call within an agent trace.

    Attributes:
        model: Model identifier (e.g., 'gpt-4', 'claude-3-opus').
        messages: Serialized message array (JSON string). Contains both
            the prompt and any tool results injected by the agent framework.
        completion: Serialized completion output (JSON string).
        prompt_tokens: Number of prompt tokens consumed.
        completion_tokens: Number of completion tokens generated.
        timestamp: Unix epoch timestamp.
        span_id: OTel span identifier.
        trace_id: Parent trace identifier.
        parent_span_id: Parent span ID.
        duration_ms: Call duration in milliseconds.
        metadata: Additional key-value metadata.
    """

    model: str = ""
    messages: str = ""
    completion: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    timestamp: float = 0.0
    span_id: str = ""
    trace_id: str = ""
    parent_span_id: str = ""
    duration_ms: float = 0.0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def step_type(self) -> StepType:
        """Return the step type discriminator."""
        return StepType.LLM_CALL


# Union type for trace steps
TraceStep = ToolCall | LLMCall


@dataclass(frozen=True)
class Trace:
    """A complete, ordered execution trace from an agent runtime.

    A Trace represents one full agent interaction — from the initial user
    prompt through all tool calls and LLM invocations to the final response.
    Steps are ordered by timestamp.

    Attributes:
        trace_id: Unique identifier for this trace (from OTel trace ID).
        steps: Ordered sequence of tool calls and LLM calls.
        start_time: Unix epoch timestamp of the first step.
        end_time: Unix epoch timestamp of the last step.
        metadata: Trace-level metadata (agent name, session ID, etc.).
    """

    trace_id: str
    steps: tuple[TraceStep, ...] = ()
    start_time: float = 0.0
    end_time: float = 0.0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def tool_calls(self) -> list[ToolCall]:
        """Extract all tool calls from the trace, in order."""
        return [s for s in self.steps if isinstance(s, ToolCall)]

    @property
    def llm_calls(self) -> list[LLMCall]:
        """Extract all LLM calls from the trace, in order."""
        return [s for s in self.steps if isinstance(s, LLMCall)]

    @property
    def duration_ms(self) -> float:
        """Total trace duration in milliseconds."""
        if self.end_time > 0 and self.start_time > 0:
            return (self.end_time - self.start_time) * 1000
        return 0.0

    def __len__(self) -> int:
        """Return the number of steps in this trace."""
        return len(self.steps)

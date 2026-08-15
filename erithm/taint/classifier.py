"""
Heuristic classifier for Erithm taint analysis.

Provides regex/pattern-based detection of prompt injection patterns in
tool outputs. This is the primary classifier for obvious injection
attempts, and serves as the fallback when the LM-judge is unavailable
or fails.

Detection categories:
    1. Instruction override — "ignore previous instructions", "you are now"
    2. Role manipulation — "system:", "assistant:", role-switching attempts
    3. Data exfiltration — encoded URLs, base64 payloads in tool args
    4. Command injection — shell commands, code execution patterns
    5. Social engineering — urgency/authority patterns targeting the LLM

Security:
    - Pattern matching uses pre-compiled regex for performance.
    - Content snippets in results are truncated to 200 chars max.
    - No raw content is logged at INFO level or below.
"""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from erithm.taint.labels import TaintLabel, TaintInfo

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClassificationResult:
    """Result of a taint classification attempt.

    Attributes:
        is_injection: Whether injection was detected.
        taint_label: Assigned taint label.
        confidence: Confidence score (0.0–1.0).
        reason: Human-readable explanation.
        matched_patterns: Names of patterns that matched.
        classifier: Which classifier produced this result.
    """

    is_injection: bool
    taint_label: TaintLabel
    confidence: float
    reason: str
    matched_patterns: tuple[str, ...] = ()
    classifier: str = "heuristic"


class BaseClassifier(ABC):
    """Abstract base class for taint classifiers.

    All classifiers implement the ``classify`` method that takes a
    content string and returns a ClassificationResult.
    """

    @abstractmethod
    def classify(self, content: str, context: dict[str, str] | None = None) -> ClassificationResult:
        """Classify content for prompt injection.

        Args:
            content: The content string to classify (tool output, args, etc.).
            context: Optional context about the tool call (name, trace info).

        Returns:
            A ClassificationResult with the classification decision.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this classifier is operational.

        Returns:
            True if the classifier can process classifications.
        """
        ...


# --- Injection detection patterns ---
# Each pattern is a tuple of (category, name, compiled_regex, confidence, description)

@dataclass(frozen=True)
class _Pattern:
    """A single injection detection pattern."""

    category: str
    name: str
    regex: re.Pattern[str]
    confidence: float
    description: str


_INJECTION_PATTERNS: list[_Pattern] = [
    # Category 1: Instruction override
    _Pattern(
        category="instruction_override",
        name="ignore_instructions",
        regex=re.compile(
            r"(?i)"
            r"(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:all\s+)?"
            r"(?:previous|prior|above|earlier|original|your)\s+"
            r"(?:instructions?|rules?|guidelines?|constraints?|directives?|prompts?)"
        ),
        confidence=0.95,
        description="Attempts to override the LLM's original instructions",
    ),
    _Pattern(
        category="instruction_override",
        name="new_instructions",
        regex=re.compile(
            r"(?i)"
            r"(?:your\s+new\s+(?:instructions?|task|role|objective))"
            r"|(?:from\s+now\s+on\s+you\s+(?:will|should|must|are))"
            r"|(?:you\s+are\s+now\s+(?:a|an|the))"
            r"|(?:act\s+as\s+(?:a|an|the|if))"
        ),
        confidence=0.90,
        description="Attempts to assign new instructions or role to the LLM",
    ),
    _Pattern(
        category="instruction_override",
        name="do_not_pattern",
        regex=re.compile(
            r"(?i)"
            r"(?:do\s+not|don'?t)\s+"
            r"(?:follow|obey|listen\s+to|comply\s+with)\s+"
            r"(?:the\s+)?"
            r"(?:user'?s?|original|previous|prior|system)"
        ),
        confidence=0.90,
        description="Instructs the LLM to ignore the user's or system's directives",
    ),

    # Category 2: Role manipulation
    _Pattern(
        category="role_manipulation",
        name="system_prompt_injection",
        regex=re.compile(
            r"(?i)"
            r"(?:^|\n)\s*(?:system|assistant|SYSTEM|ASSISTANT)\s*:"
            r"|(?:\[SYSTEM\]|\[INST\]|\[/INST\])"
            r"|(?:<\|system\|>|<\|assistant\|>|<\|user\|>)"
        ),
        confidence=0.85,
        description="Attempts to inject system/assistant role markers",
    ),
    _Pattern(
        category="role_manipulation",
        name="delimiter_injection",
        regex=re.compile(
            r"(?i)"
            r"(?:```\s*system)|(?:---\s*system\s*---)"
            r"|(?:<<\s*SYS\s*>>)|(?:\[SYSTEM_PROMPT\])"
            r"|(?:BEGIN\s+SYSTEM\s+PROMPT)"
        ),
        confidence=0.90,
        description="Attempts to inject system prompt delimiters",
    ),

    # Category 3: Data exfiltration
    _Pattern(
        category="data_exfiltration",
        name="url_exfiltration",
        regex=re.compile(
            r"(?i)"
            r"(?:https?://[^\s]+\?.*(?:data|token|key|secret|password|cred)=[^\s&]+)"
            r"|(?:fetch|curl|wget|request)\s+(?:https?://)"
            r"|(?:send\s+(?:the\s+)?(?:data|info|content|results?)\s+to\s+https?://)"
        ),
        confidence=0.85,
        description="Attempts to exfiltrate data via URL",
    ),
    _Pattern(
        category="data_exfiltration",
        name="encode_exfiltration",
        regex=re.compile(
            r"(?i)"
            r"(?:base64|hex|url)\s*[\._-]?\s*(?:encode|decode)\s*\("
            r"|(?:encode\s+(?:the\s+)?(?:data|content|response|output)\s+(?:as|in|to)\s+(?:base64|hex))"
        ),
        confidence=0.80,
        description="Attempts to encode data for exfiltration",
    ),

    # Category 4: Command injection
    _Pattern(
        category="command_injection",
        name="shell_commands",
        regex=re.compile(
            r"(?i)"
            r"(?:execute|run|call|invoke)\s+"
            r"(?:the\s+)?(?:following\s+)?"
            r"(?:shell\s+)?(?:command|script|code)"
            r"|(?:```\s*(?:bash|sh|shell|cmd|powershell)\s*\n)"
        ),
        confidence=0.85,
        description="Attempts to inject shell command execution",
    ),
    _Pattern(
        category="command_injection",
        name="dangerous_operations",
        regex=re.compile(
            r"(?i)"
            r"(?:rm\s+-rf|sudo\s+|chmod\s+777|dd\s+if=)"
            r"|(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE)"
            r"|(?:eval\(|exec\(|__import__\(|os\.system\()"
        ),
        confidence=0.95,
        description="Dangerous system operation patterns",
    ),

    # Category 5: Social engineering / authority patterns
    _Pattern(
        category="social_engineering",
        name="urgency_authority",
        regex=re.compile(
            r"(?i)"
            r"(?:this\s+is\s+(?:urgent|critical|emergency|important))"
            r"|(?:(?:I\s+am|this\s+is)\s+(?:the\s+)?(?:admin|administrator|root|system|developer|owner))"
            r"|(?:(?:authorized|approved|permitted)\s+by\s+(?:the\s+)?(?:admin|system|owner))"
        ),
        confidence=0.70,
        description="Social engineering via urgency or authority claims",
    ),

    # Category 6: Prompt leaking
    _Pattern(
        category="prompt_leak",
        name="prompt_extraction",
        regex=re.compile(
            r"(?i)"
            r"(?:(?:reveal|show|display|output|print|repeat|echo)\s+"
            r"(?:the\s+)?(?:system\s+)?(?:prompt|instructions|rules|guidelines))"
            r"|(?:what\s+(?:are|is)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules))"
        ),
        confidence=0.75,
        description="Attempts to extract the system prompt",
    ),
]


class HeuristicClassifier(BaseClassifier):
    """Pattern-based classifier for obvious prompt injection detection.

    Uses pre-compiled regex patterns across multiple detection categories
    to identify known injection patterns. Operates entirely locally with
    no external API calls.

    This classifier serves as:
        1. The primary classifier in HEURISTIC mode.
        2. The fallback classifier when the LM-judge is unavailable.
        3. A pre-filter before LM-judge classification (obvious cases
           don't need LLM evaluation).

    Attributes:
        confidence_threshold: Minimum pattern confidence to trigger detection.
        min_content_length: Minimum content length to classify (very short
            content is unlikely to contain injection).
    """

    def __init__(
        self,
        confidence_threshold: float = 0.7,
        min_content_length: int = 10,
    ) -> None:
        """Initialize the heuristic classifier.

        Args:
            confidence_threshold: Minimum confidence to flag as injection.
            min_content_length: Minimum content length to analyze.
        """
        self._confidence_threshold = confidence_threshold
        self._min_content_length = min_content_length

    def classify(
        self, content: str, context: dict[str, str] | None = None
    ) -> ClassificationResult:
        """Classify content for prompt injection using heuristic patterns.

        Args:
            content: Content string to analyze.
            context: Optional context (tool name, trace info).

        Returns:
            ClassificationResult with detection decision.
        """
        if not content or len(content) < self._min_content_length:
            return ClassificationResult(
                is_injection=False,
                taint_label=TaintLabel.CLEAN,
                confidence=1.0,
                reason="Content too short for injection analysis",
                classifier="heuristic",
            )

        matched: list[_Pattern] = []

        for pattern in _INJECTION_PATTERNS:
            if pattern.regex.search(content):
                if pattern.confidence >= self._confidence_threshold:
                    matched.append(pattern)

        if not matched:
            return ClassificationResult(
                is_injection=False,
                taint_label=TaintLabel.EXTERNAL,
                confidence=0.6,
                reason="No injection patterns detected",
                classifier="heuristic",
            )

        # Use the highest-confidence match
        best_match = max(matched, key=lambda p: p.confidence)

        # Multiple matches increase overall confidence
        aggregate_confidence = min(
            best_match.confidence + (len(matched) - 1) * 0.05, 1.0
        )

        matched_names = tuple(p.name for p in matched)
        categories = sorted(set(p.category for p in matched))

        return ClassificationResult(
            is_injection=True,
            taint_label=TaintLabel.INJECTION,
            confidence=aggregate_confidence,
            reason=(
                f"Detected {len(matched)} injection pattern(s) in categories: "
                f"{', '.join(categories)}. Primary: {best_match.description}"
            ),
            matched_patterns=matched_names,
            classifier="heuristic",
        )

    def is_available(self) -> bool:
        """Heuristic classifier is always available."""
        return True

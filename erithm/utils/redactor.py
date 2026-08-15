"""
Content redaction utilities for Erithm.

Strips or masks sensitive content from span events before export.
Implements the PRD Section 7 requirement: "Don't persist raw prompt/tool
content in span attributes."

Redaction patterns cover:
    - API keys and tokens (Bearer, sk-*, key-* prefixes)
    - Common PII patterns (email, phone, SSN)
    - Base64-encoded payloads above a size threshold
    - Custom patterns defined in policy

Security:
    - Redaction is applied before any content is logged or exported.
    - The redactor itself never logs the content it redacts.
    - Pattern matching uses compiled regex for performance.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# Pre-compiled redaction patterns for performance
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # API keys and tokens
    ("API_KEY", re.compile(
        r"(?i)"
        r"(?:sk-[a-zA-Z0-9]{20,})"
        r"|(?:key-[a-zA-Z0-9]{20,})"
        r"|(?:Bearer\s+[a-zA-Z0-9._\-]{20,})"
        r"|(?:token[=:\s]+[a-zA-Z0-9._\-]{20,})"
        r"|(?:api[_-]?key[=:\s]+[a-zA-Z0-9._\-]{10,})"
    )),
    # Email addresses
    ("EMAIL", re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
    )),
    # Phone numbers (US format)
    ("PHONE", re.compile(
        r"(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}"
    )),
    # SSN
    ("SSN", re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    )),
    # Credit card numbers (basic pattern)
    ("CREDIT_CARD", re.compile(
        r"\b(?:\d{4}[\s-]?){3}\d{4}\b"
    )),
    # Base64 payloads (long strings that look like base64)
    ("BASE64_PAYLOAD", re.compile(
        r"(?:[A-Za-z0-9+/]{64,})(?:={0,2})"
    )),
]

# Replacement template
_REDACTED_TEMPLATE = "[REDACTED:{tag}]"


@dataclass
class ContentRedactor:
    """Redacts sensitive content from strings before logging or export.

    Applies a chain of regex-based redaction patterns to strip API keys,
    PII, and other sensitive content. Custom patterns can be added for
    domain-specific redaction.

    Attributes:
        enabled: Whether redaction is active. Defaults to True.
        custom_patterns: Additional redaction patterns (tag → regex string).
        max_content_length: Maximum content length after redaction.
            Content exceeding this is truncated with a marker.
    """

    enabled: bool = True
    custom_patterns: dict[str, str] = field(default_factory=dict)
    max_content_length: int = 10_000

    def __post_init__(self) -> None:
        """Compile custom patterns on construction."""
        self._compiled_custom: list[tuple[str, re.Pattern[str]]] = []
        for tag, pattern_str in self.custom_patterns.items():
            try:
                compiled = re.compile(pattern_str)
                self._compiled_custom.append((tag, compiled))
            except re.error as e:
                logger.warning(
                    "Invalid custom redaction pattern '%s': %s", tag, e
                )

    def redact(self, content: str) -> str:
        """Apply all redaction patterns to the content string.

        Args:
            content: Raw content string to redact.

        Returns:
            Redacted content with sensitive values replaced by
            ``[REDACTED:TAG]`` markers.
        """
        if not self.enabled or not content:
            return content

        result = content

        # Apply built-in patterns
        for tag, pattern in _PATTERNS:
            result = pattern.sub(_REDACTED_TEMPLATE.format(tag=tag), result)

        # Apply custom patterns
        for tag, pattern in self._compiled_custom:
            result = pattern.sub(_REDACTED_TEMPLATE.format(tag=tag), result)

        # Truncate if exceeding max length
        if len(result) > self.max_content_length:
            result = result[: self.max_content_length] + "\n[TRUNCATED]"

        return result

    def redact_dict(self, data: dict[str, str]) -> dict[str, str]:
        """Redact all string values in a dictionary.

        Args:
            data: Dictionary with string values to redact.

        Returns:
            New dictionary with redacted values.
        """
        return {k: self.redact(v) if isinstance(v, str) else v for k, v in data.items()}

    def create_snippet(self, content: str, max_length: int = 200) -> str:
        """Create a redacted, truncated snippet for audit logs.

        Args:
            content: Raw content string.
            max_length: Maximum snippet length.

        Returns:
            Redacted and truncated snippet string.
        """
        redacted = self.redact(content)
        if len(redacted) <= max_length:
            return redacted
        return redacted[: max_length - 3] + "..."

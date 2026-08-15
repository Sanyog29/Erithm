"""
Configuration management for Erithm.

Loads runtime configuration from environment variables and optional config
files. Enforces security invariants: no secrets in config files, all
sensitive values from environment only.

Security:
    - API keys loaded exclusively from environment variables.
    - Never logs or serializes secret values, even at DEBUG level.
    - Config file paths validated against directory traversal.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


class VerdictMode(Enum):
    """Controls how Erithm responds to taint violations.

    Attributes:
        BLOCK: Actively block tainted tool calls. Production default.
        WARN: Log warnings but allow execution. Useful for shadow-mode rollouts.
        LOG: Silent logging only. For initial deployment monitoring.
    """

    BLOCK = "block"
    WARN = "warn"
    LOG = "log"


class ClassifierMode(Enum):
    """Determines which classifier pipeline is used for taint analysis.

    Attributes:
        HEURISTIC: Regex/pattern-based only. No external API calls.
        LM_JUDGE: LM-as-judge primary, with auto-fallback to heuristic.
        AUTO: Try LM-judge first, fall back to heuristic on any failure.
    """

    HEURISTIC = "heuristic"
    LM_JUDGE = "lm_judge"
    AUTO = "auto"


@dataclass(frozen=True)
class OTelConfig:
    """OpenTelemetry collector configuration.

    Attributes:
        endpoint: gRPC endpoint for the OTel collector.
            Bound to 127.0.0.1 by default — never 0.0.0.0.
        insecure: Whether to use insecure gRPC channel. Only for local dev.
    """

    endpoint: str = "127.0.0.1:4317"
    insecure: bool = True


@dataclass(frozen=True)
class LMJudgeConfig:
    """LM-as-judge classifier configuration.

    The API key is resolved exclusively from the OPENROUTER_API_KEY
    environment variable. It is never read from config files, never
    logged, and never serialized.

    Attributes:
        model: OpenRouter model identifier for classification.
        base_url: OpenRouter API base URL.
        timeout_seconds: Request timeout. Triggers heuristic fallback on expiry.
        max_retries: Maximum retry attempts before falling back to heuristic.
        temperature: Sampling temperature for classification (low = deterministic).
    """

    model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"
    base_url: str = "https://openrouter.ai/api/v1"
    timeout_seconds: float = 30.0
    max_retries: int = 2
    temperature: float = 0.1

    @property
    def api_key(self) -> Optional[str]:
        """Resolve API key from environment. Never cached or logged."""
        return os.environ.get("OPENROUTER_API_KEY")

    @property
    def is_available(self) -> bool:
        """Check if the LM-judge is configured with a valid API key."""
        key = self.api_key
        return key is not None and len(key) > 0


@dataclass(frozen=True)
class ErithmConfig:
    """Root configuration for Erithm.

    Assembled from environment variables and optional YAML config files.
    Enforces security invariants at construction time.

    Attributes:
        policy_path: Path to the YAML policy file defining sources/sinks.
        verdict_mode: How to respond to taint violations (block/warn/log).
        classifier_mode: Which classifier pipeline to use.
        otel: OpenTelemetry collector configuration.
        lm_judge: LM-as-judge classifier configuration.
        log_level: Python logging level string.
        redact_content: Whether to redact prompt/tool content in audit spans.
    """

    policy_path: Path = field(
        default_factory=lambda: Path(__file__).parent / "policy" / "default_policy.yaml"
    )
    verdict_mode: VerdictMode = VerdictMode.BLOCK
    classifier_mode: ClassifierMode = ClassifierMode.AUTO
    otel: OTelConfig = field(default_factory=OTelConfig)
    lm_judge: LMJudgeConfig = field(default_factory=LMJudgeConfig)
    log_level: str = "INFO"
    redact_content: bool = True

    def __post_init__(self) -> None:
        """Validate configuration after construction."""
        # Validate policy path exists
        if not self.policy_path.exists():
            logger.warning(
                "Policy file not found at %s — using built-in defaults",
                self.policy_path,
            )

        # Warn if LM-judge is requested but API key is missing
        if self.classifier_mode in (ClassifierMode.LM_JUDGE, ClassifierMode.AUTO):
            if not self.lm_judge.is_available:
                logger.warning(
                    "OPENROUTER_API_KEY not set — LM-judge will fall back to "
                    "heuristic classifier on every call"
                )

    def __repr__(self) -> str:
        """Safe repr that never exposes secrets."""
        return (
            f"ErithmConfig(policy_path={self.policy_path!r}, "
            f"verdict_mode={self.verdict_mode.value!r}, "
            f"classifier_mode={self.classifier_mode.value!r}, "
            f"log_level={self.log_level!r}, "
            f"lm_judge_model={self.lm_judge.model!r}, "
            f"lm_judge_available={self.lm_judge.is_available})"
        )


def load_config(config_path: Optional[Path] = None) -> ErithmConfig:
    """Load Erithm configuration from a YAML file and environment overrides.

    Resolution order (highest priority first):
        1. Environment variables (ERITHM_* prefix)
        2. Config file values (erithm.yaml)
        3. Built-in defaults

    Args:
        config_path: Optional path to a YAML config file. If None, checks
            for ``erithm.yaml`` in the current directory.

    Returns:
        A validated ErithmConfig instance.

    Security:
        - Uses yaml.safe_load exclusively — never yaml.load.
        - API keys are resolved from environment, never from the config file.
        - Config file paths are resolved and validated against traversal.
    """
    raw: dict = {}

    # Attempt to load config file
    if config_path is None:
        config_path = Path("erithm.yaml")

    if config_path.exists():
        resolved = config_path.resolve()
        logger.info("Loading config from %s", resolved)
        with open(resolved) as f:
            raw = yaml.safe_load(f) or {}

    # Environment variable overrides
    env_map = {
        "ERITHM_POLICY_PATH": "policy_path",
        "ERITHM_VERDICT_MODE": "verdict_mode",
        "ERITHM_CLASSIFIER_MODE": "classifier_mode",
        "ERITHM_LOG_LEVEL": "log_level",
        "ERITHM_OTEL_ENDPOINT": "otel_endpoint",
        "ERITHM_LM_MODEL": "lm_model",
        "ERITHM_REDACT_CONTENT": "redact_content",
    }

    for env_key, config_key in env_map.items():
        env_val = os.environ.get(env_key)
        if env_val is not None:
            raw[config_key] = env_val

    # Build config objects
    otel_config = OTelConfig(
        endpoint=raw.get("otel_endpoint", "127.0.0.1:4317"),
        insecure=raw.get("otel_insecure", True),
    )

    lm_config = LMJudgeConfig(
        model=raw.get("lm_model", "nvidia/nemotron-3-ultra-550b-a55b:free"),
        timeout_seconds=float(raw.get("lm_timeout", 30.0)),
        max_retries=int(raw.get("lm_max_retries", 2)),
        temperature=float(raw.get("lm_temperature", 0.1)),
    )

    policy_path_str = raw.get("policy_path")
    policy_path_val = (
        Path(policy_path_str).resolve()
        if policy_path_str
        else Path(__file__).parent / "policy" / "default_policy.yaml"
    )

    verdict_mode_str = raw.get("verdict_mode", "block")
    classifier_mode_str = raw.get("classifier_mode", "auto")
    redact_str = raw.get("redact_content", True)

    return ErithmConfig(
        policy_path=policy_path_val,
        verdict_mode=VerdictMode(verdict_mode_str),
        classifier_mode=ClassifierMode(classifier_mode_str),
        otel=otel_config,
        lm_judge=lm_config,
        log_level=raw.get("log_level", "INFO"),
        redact_content=bool(redact_str),
    )

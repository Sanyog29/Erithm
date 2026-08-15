"""
YAML policy file loader for Erithm.

Loads security policies from YAML files with strict schema validation.
Supports merging user policies with the built-in default policy.

Security:
    - Uses yaml.safe_load exclusively — never yaml.load.
    - Validates all fields against expected types.
    - Policy file paths are resolved and validated.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from erithm.policy.models import (
    Policy,
    SourceRule,
    SinkRule,
    SinkAction,
    PolicySettings,
)

logger = logging.getLogger(__name__)

# Path to the built-in default policy
_DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"


class PolicyLoader:
    """Loads and validates Erithm security policies from YAML files.

    Supports loading from files, dictionaries, or merging multiple
    policies. Always uses yaml.safe_load for security.

    Example:
        loader = PolicyLoader()
        policy = loader.load_file("my_policy.yaml")
        print(f"Loaded {len(policy.sources)} sources, {len(policy.sinks)} sinks")
    """

    def load_file(self, path: str | Path) -> Policy:
        """Load a policy from a YAML file.

        Args:
            path: Path to the YAML policy file.

        Returns:
            Validated Policy object.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file contains invalid policy data.
        """
        resolved = Path(path).resolve()

        if not resolved.exists():
            raise FileNotFoundError(f"Policy file not found: {resolved}")

        logger.info("Loading policy from %s", resolved.name)

        with open(resolved, encoding="utf-8") as f:
            # Security: yaml.safe_load only — never yaml.load
            raw = yaml.safe_load(f)

        if raw is None:
            raise ValueError(f"Empty policy file: {resolved.name}")

        return self.load_dict(raw)

    def load_dict(self, raw: dict[str, Any]) -> Policy:
        """Load a policy from a parsed dictionary.

        Args:
            raw: Parsed YAML data dictionary.

        Returns:
            Validated Policy object.

        Raises:
            ValueError: If the data contains invalid policy fields.
        """
        if not isinstance(raw, dict):
            raise ValueError(f"Policy must be a YAML mapping, got {type(raw).__name__}")

        # Parse version
        version = str(raw.get("version", "1.0"))

        # Parse source rules
        sources = tuple(
            self._parse_source_rule(s)
            for s in raw.get("sources", [])
            if isinstance(s, dict)
        )

        # Parse sink rules
        sinks = tuple(
            self._parse_sink_rule(s)
            for s in raw.get("sinks", [])
            if isinstance(s, dict)
        )

        # Parse settings
        settings = self._parse_settings(raw.get("settings", {}))

        # Parse metadata
        metadata = {
            str(k): str(v)
            for k, v in raw.get("metadata", {}).items()
        } if isinstance(raw.get("metadata"), dict) else {}

        policy = Policy(
            version=version,
            sources=sources,
            sinks=sinks,
            settings=settings,
            metadata=metadata,
        )

        logger.info(
            "Loaded policy v%s: %d sources, %d sinks",
            version,
            len(sources),
            len(sinks),
        )

        return policy

    def load_default(self) -> Policy:
        """Load the built-in default policy.

        Returns:
            The default Policy with production-level sink/source rules.
        """
        if _DEFAULT_POLICY_PATH.exists():
            return self.load_file(_DEFAULT_POLICY_PATH)

        logger.warning("Default policy file not found — using minimal built-in policy")
        return self._minimal_policy()

    def merge(self, base: Policy, override: Policy) -> Policy:
        """Merge two policies, with override taking precedence.

        Override rules replace base rules with the same name.
        New rules in override are appended.

        Args:
            base: Base policy (typically the default).
            override: Override policy (user-defined).

        Returns:
            Merged Policy.
        """
        # Merge sources
        base_sources = {s.name: s for s in base.sources}
        for s in override.sources:
            base_sources[s.name] = s

        # Merge sinks
        base_sinks = {s.name: s for s in base.sinks}
        for s in override.sinks:
            base_sinks[s.name] = s

        return Policy(
            version=override.version or base.version,
            sources=tuple(base_sources.values()),
            sinks=tuple(base_sinks.values()),
            settings=override.settings if override.settings != PolicySettings() else base.settings,
            metadata={**base.metadata, **override.metadata},
        )

    def _parse_source_rule(self, data: dict[str, Any]) -> SourceRule:
        """Parse a source rule from YAML data.

        Args:
            data: Source rule dictionary.

        Returns:
            Validated SourceRule.
        """
        return SourceRule(
            name=str(data.get("name", "unnamed_source")),
            pattern=str(data.get("pattern", "*")),
            taint_level=str(data.get("taint_level", "external")),
            description=str(data.get("description", "")),
        )

    def _parse_sink_rule(self, data: dict[str, Any]) -> SinkRule:
        """Parse a sink rule from YAML data.

        Args:
            data: Sink rule dictionary.

        Returns:
            Validated SinkRule.
        """
        action_str = str(data.get("action", "block")).lower()
        try:
            action = SinkAction(action_str)
        except ValueError:
            logger.warning(
                "Unknown sink action '%s' — defaulting to 'block'", action_str
            )
            action = SinkAction.BLOCK

        return SinkRule(
            name=str(data.get("name", "unnamed_sink")),
            pattern=str(data.get("pattern", "")),
            action=action,
            min_taint_level=str(data.get("min_taint_level", "external")),
            description=str(data.get("description", "")),
            owasp_ref=str(data.get("owasp_ref", "")),
        )

    def _parse_settings(self, data: Any) -> PolicySettings:
        """Parse global settings from YAML data.

        Args:
            data: Settings dictionary or None.

        Returns:
            PolicySettings object.
        """
        if not isinstance(data, dict):
            return PolicySettings()

        return PolicySettings(
            default_source_taint=str(data.get("default_source_taint", "external")),
            enable_implicit_flow_tracking=bool(data.get("enable_implicit_flow_tracking", True)),
            max_propagation_depth=int(data.get("max_propagation_depth", 50)),
            classifier_confidence_threshold=float(data.get("classifier_confidence_threshold", 0.7)),
        )

    @staticmethod
    def _minimal_policy() -> Policy:
        """Create a minimal built-in policy as absolute fallback.

        Returns:
            A Policy with basic source/sink rules.
        """
        return Policy(
            version="1.0",
            sources=(
                SourceRule(name="web_search", pattern="*search*", taint_level="external"),
                SourceRule(name="retrieval", pattern="*retrieve*", taint_level="external"),
            ),
            sinks=(
                SinkRule(name="email", pattern="*email*", action=SinkAction.BLOCK),
                SinkRule(name="shell", pattern="*shell*", action=SinkAction.BLOCK),
                SinkRule(name="exec", pattern="*exec*", action=SinkAction.BLOCK),
            ),
        )

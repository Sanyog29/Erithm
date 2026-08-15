"""
AgentDojo benchmark runner for Erithm.

Scaffolded infrastructure for running Erithm against the AgentDojo
benchmark suite. The runner loads AgentDojo traces, runs the full
Erithm pipeline, and produces metrics (detection rate, false-positive
rate, latency).

This module is infrastructure for Week 5 of the project timeline.
The actual AgentDojo dataset needs to be obtained separately.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkCase:
    """A single benchmark test case.

    Attributes:
        case_id: Unique identifier for the test case.
        trace_data: Raw trace data (spans) for this case.
        is_attack: Ground truth — whether this case contains an attack.
        attack_type: Type of attack (if is_attack is True).
        description: Human-readable case description.
    """

    case_id: str
    trace_data: list[dict[str, Any]]
    is_attack: bool
    attack_type: str = ""
    description: str = ""


@dataclass
class BenchmarkResult:
    """Results from running the benchmark.

    Attributes:
        total_cases: Total number of test cases.
        true_positives: Attacks correctly detected.
        false_positives: Benign cases incorrectly flagged.
        true_negatives: Benign cases correctly allowed.
        false_negatives: Attacks that were missed.
        avg_latency_ms: Average analysis latency per case.
        case_results: Per-case results for detailed analysis.
    """

    total_cases: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    avg_latency_ms: float = 0.0
    case_results: list[dict[str, Any]] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        """True positive rate (sensitivity/recall)."""
        total_attacks = self.true_positives + self.false_negatives
        if total_attacks == 0:
            return 0.0
        return self.true_positives / total_attacks

    @property
    def false_positive_rate(self) -> float:
        """False positive rate."""
        total_benign = self.true_negatives + self.false_positives
        if total_benign == 0:
            return 0.0
        return self.false_positives / total_benign

    @property
    def precision(self) -> float:
        """Precision (positive predictive value)."""
        total_flagged = self.true_positives + self.false_positives
        if total_flagged == 0:
            return 0.0
        return self.true_positives / total_flagged

    @property
    def f1_score(self) -> float:
        """F1 score (harmonic mean of precision and recall)."""
        p = self.precision
        r = self.detection_rate
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    def summary(self) -> str:
        """Human-readable summary of benchmark results."""
        return (
            f"Benchmark Results\n"
            f"{'─' * 40}\n"
            f"Total cases:       {self.total_cases}\n"
            f"True positives:    {self.true_positives}\n"
            f"False positives:   {self.false_positives}\n"
            f"True negatives:    {self.true_negatives}\n"
            f"False negatives:   {self.false_negatives}\n"
            f"{'─' * 40}\n"
            f"Detection rate:    {self.detection_rate:.1%}\n"
            f"False positive rate: {self.false_positive_rate:.1%}\n"
            f"Precision:         {self.precision:.1%}\n"
            f"F1 score:          {self.f1_score:.3f}\n"
            f"Avg latency:       {self.avg_latency_ms:.1f}ms\n"
        )


class BenchmarkRunner:
    """Runs Erithm against the AgentDojo benchmark suite.

    This is scaffolded infrastructure. To run the benchmark:
        1. Obtain the AgentDojo dataset
        2. Convert cases to BenchmarkCase format
        3. Call runner.run(cases)

    Example:
        runner = BenchmarkRunner()
        cases = runner.load_agentdojo("path/to/agentdojo/")
        result = runner.run(cases)
        print(result.summary())
    """

    def __init__(self) -> None:
        """Initialize the benchmark runner."""
        # Lazy import to avoid circular dependency
        self._interceptor = None

    def _get_interceptor(self):
        """Lazy-initialize the interceptor."""
        if self._interceptor is None:
            from erithm.config import ErithmConfig, ClassifierMode
            from erithm.middleware.interceptor import ErithmInterceptor

            config = ErithmConfig(
                classifier_mode=ClassifierMode.HEURISTIC,
                log_level="WARNING",
            )
            self._interceptor = ErithmInterceptor(config=config)
        return self._interceptor

    def run(self, cases: list[BenchmarkCase]) -> BenchmarkResult:
        """Run the benchmark on a list of test cases.

        Args:
            cases: List of BenchmarkCase objects.

        Returns:
            BenchmarkResult with aggregate metrics.
        """
        interceptor = self._get_interceptor()
        result = BenchmarkResult(total_cases=len(cases))
        latencies: list[float] = []

        for case in cases:
            start = time.time()

            try:
                analysis = interceptor.analyze_trace(case.trace_data)
                detected = analysis.violations_found > 0
            except Exception as e:
                logger.error("Error analyzing case %s: %s", case.case_id, e)
                detected = False

            elapsed = (time.time() - start) * 1000
            latencies.append(elapsed)

            # Classify result
            if case.is_attack and detected:
                result.true_positives += 1
            elif case.is_attack and not detected:
                result.false_negatives += 1
            elif not case.is_attack and detected:
                result.false_positives += 1
            else:
                result.true_negatives += 1

            result.case_results.append({
                "case_id": case.case_id,
                "is_attack": case.is_attack,
                "detected": detected,
                "correct": (case.is_attack == detected),
                "latency_ms": elapsed,
            })

        result.avg_latency_ms = sum(latencies) / len(latencies) if latencies else 0.0

        logger.info("Benchmark complete:\n%s", result.summary())
        return result

    def load_agentdojo(self, dataset_path: str | Path) -> list[BenchmarkCase]:
        """Load AgentDojo dataset and convert to BenchmarkCase format.

        This method needs to be implemented based on the actual AgentDojo
        data format once the dataset is obtained.

        Args:
            dataset_path: Path to the AgentDojo dataset directory.

        Returns:
            List of BenchmarkCase objects.

        Raises:
            NotImplementedError: Until AgentDojo format is integrated.
        """
        path = Path(dataset_path)
        if not path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        # TODO: Implement AgentDojo format parsing
        # The AgentDojo dataset format needs to be mapped to our
        # BenchmarkCase structure. Expected fields:
        #   - task_id, trace, is_injection, injection_type
        raise NotImplementedError(
            "AgentDojo format parsing not yet implemented. "
            "Obtain the dataset and implement the mapping in this method."
        )

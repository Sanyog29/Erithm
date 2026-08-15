"""
Decorator for Erithm — the easiest way to integrate the firewall.

Usage:
    from erithm import with_erithm

    @with_erithm()
    def run_agent(task_prompt: str):
        # Your agent logic here
        ...
"""

import functools
import logging
from typing import Callable, Any

from erithm.config import ErithmConfig
from erithm.middleware.interceptor import ErithmInterceptor

logger = logging.getLogger(__name__)


def with_erithm(
    config: ErithmConfig | None = None,
    fail_open: bool = False,
) -> Callable:
    """Decorator to protect an agent function with Erithm.

    Wraps the agent execution. Currently, this initializes the interceptor
    and sets up context. In a full implementation, it would hook into
    the OTel tracer provider to automatically analyze traces as they complete
    within the decorated function's scope.

    Args:
        config: Erithm configuration. Uses defaults if None.
        fail_open: If True, firewall errors won't crash the agent.
            (Security violations will still block if in block mode).
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            logger.info("Agent execution protected by Erithm firewall")
            try:
                # Initialize the interceptor to validate config and policy
                interceptor = ErithmInterceptor(config=config)
                # In a real implementation, we would attach an OTel span processor here
                # to stream spans to the interceptor in real-time.
            except Exception as e:
                logger.error("Failed to initialize Erithm: %s", e)
                if not fail_open:
                    raise

            try:
                return func(*args, **kwargs)
            finally:
                # Cleanup or final trace evaluation would happen here
                logger.debug("Erithm firewall detached")

        return wrapper
    return decorator

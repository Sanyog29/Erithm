"""
Middleware module — agent integration layer.

Provides the drop-in ErithmInterceptor that orchestrates the full
Erithm pipeline (ingest → graph → taint → verdict) for agent runtimes.
"""

from erithm.middleware.interceptor import ErithmInterceptor

__all__ = [
    "ErithmInterceptor",
]

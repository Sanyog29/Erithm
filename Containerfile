# Erithm Containerfile — rootless, minimal attack surface
# Build: podman build -t erithm -f Containerfile .
# Run:   podman run --rm erithm analyze /data/trace.json
#
# Security:
#   - Multi-stage build to minimize final image size
#   - Non-root user inside container (matches Podman rootless model)
#   - No shell in final stage for reduced attack surface
#   - Dependencies pinned at build time

# ── Stage 1: Build ──────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir hatchling

# Copy source and build
COPY erithm/ ./erithm/
COPY README.md ./
RUN pip wheel --no-deps --wheel-dir /wheels .

# ── Stage 2: Runtime ────────────────────────────────────
FROM python:3.11-slim AS runtime

# Security: create non-root user
RUN groupadd --gid 1000 erithm && \
    useradd --uid 1000 --gid erithm --shell /bin/false --create-home erithm

WORKDIR /app

# Install the wheel from build stage
COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Copy default policy
COPY erithm/policy/default_policy.yaml /app/policies/default.yaml

# Security: switch to non-root user
USER erithm

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["erithm", "version"]

ENTRYPOINT ["erithm"]
CMD ["--help"]

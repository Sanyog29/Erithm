<div align="center">

# 🛡️ Erithm

### Taint-Analysis Firewall for LLM Tool-Calling Agents

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![OWASP Aligned](https://img.shields.io/badge/OWASP-Aligned-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF-blue.svg)](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)

**Erithm intercepts, analyzes, and blocks prompt injection attacks that flow through tool outputs in LLM agent pipelines.**

[Quick Start](#-quick-start) · [Architecture](#-architecture) · [CLI Usage](#-cli-usage) · [Policy Guide](#-policy-configuration) · [Security](#-security-posture) · [Benchmarks](#-benchmarks)

</div>

---

## 🎯 The Problem

LLM agents call tools. Tool outputs — search results, retrieved docs, API responses — can carry **attacker-controlled content**. If that content reaches a privileged tool call (`send_email`, `execute_shell`, `transfer_funds`) unfiltered, the agent gets hijacked.

This is **prompt injection via tool output**, and it's the open problem in agentic AI security.

```
┌──────────────┐     ┌─────────────┐     ┌───────────────────────┐
│  web_search   │────▶│  LLM Call   │────▶│  send_email           │
│  (attacker-   │     │  (follows   │     │  (sends stolen data   │
│   controlled) │     │   injected  │     │   to attacker)        │
│              │     │   commands) │     │                       │
└──────────────┘     └─────────────┘     └───────────────────────┘
     SOURCE              FLOW                   SINK ← BLOCKED
```

**Erithm sits between your agent and its tools**, analyzing data flows in real-time to catch this exact attack vector.

---

## ✨ What Erithm Does

| Stage | Description |
|-------|-------------|
| **1. Ingest** | Receives OpenTelemetry GenAI spans from any instrumented agent |
| **2. Graph** | Builds a data-flow dependency graph of tool calls |
| **3. Taint** | Propagates taint labels and classifies injection patterns |
| **4. Verdict** | Blocks, warns, or logs when tainted data reaches privileged sinks |

Every verdict is logged as an OTel span — audit trail by construction, not bolted on later.

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Sanyog29/Erithm.git
cd Erithm

# Install with uv (recommended)
uv pip install -e ".[dev]"

# Or with pip
pip install -e ".[dev]"
```

### Run the Demo

```bash
# See Erithm detect a simulated prompt injection attack
python main.py
```

### Analyze a Trace File

```bash
# Analyze an exported OTel trace
erithm analyze path/to/trace.json

# JSON output for CI/CD integration
erithm analyze trace.json --output json

# Custom policy
erithm analyze trace.json --policy my_policy.yaml

# Shadow mode (warn but don't block)
erithm analyze trace.json --mode warn
```

### Python API

```python
from erithm import ErithmInterceptor

interceptor = ErithmInterceptor()
result = interceptor.analyze_trace(trace_data)

if result.has_blocks:
    raise SecurityViolation(f"Blocked: {result.verdicts}")
```

---

## 🏗️ Architecture

```
 Agent Runtime             Erithm Pipeline
┌──────────────┐  spans   ┌─────────────────────────────────────────────┐
│  Any OTel-    │────────▶│  1. Ingest    → normalize OTel spans        │
│  instrumented │         │  2. Graph     → build data-flow DiGraph     │
│  agent        │         │  3. Taint     → propagate + classify        │
│               │◀────────│  4. Verdict   → block / warn / log          │
└──────────────┘ verdict  └─────────────────────────────────────────────┘
                                    │
                                    ▼
                          ┌─────────────────┐
                          │  Audit Trail     │
                          │  (OTel spans)    │
                          └─────────────────┘
```

### Taint Propagation (Stage 3 — Core Contribution)

The taint engine uses a **lattice-based label system**:

```
CLEAN(0) < EXTERNAL(1) < USER_INPUT(2) < INJECTION(3)
```

- **Sources** (web search, retrieved docs, API responses) are marked with initial taint labels per policy.
- **Propagation** follows data-flow and implicit-flow edges through the graph using BFS.
- **Classification** uses heuristic patterns (regex) for obvious cases and an LM-as-judge (Nemotron 3 Ultra via OpenRouter) for ambiguous cases.
- **Sinks** (email, shell, financial tools) trigger enforcement when reached by tainted data.

### Implicit Flow Detection

The critical innovation: detecting taint that flows **through LLM calls**. When a tool output is injected into an LLM's context, and the LLM then generates arguments for a privileged tool call, Erithm traces this implicit data flow and flags it.

---

## 💻 CLI Usage

```bash
# Full analysis with Rich-formatted output
erithm analyze trace.json

# JSON output for programmatic use
erithm analyze trace.json --output json

# Validate a policy file
erithm policy validate my_policy.yaml

# Show effective policy (default + overrides)
erithm policy show

# Real-time monitoring (attach to OTel collector)
erithm watch --endpoint 127.0.0.1:4317

# Version info
erithm version
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No violations found (ALLOW) or non-blocking verdicts |
| `1` | Violations found with BLOCK verdict |

---

## 📋 Policy Configuration

Erithm uses a YAML-based policy DSL to define untrusted sources and privileged sinks:

```yaml
version: "1.0"

sources:
  - name: "web_search"
    pattern: "*search*"
    taint_level: "external"

  - name: "document_retrieval"
    pattern: "*retrieve*"
    taint_level: "external"

sinks:
  - name: "email"
    pattern: "*email*"
    action: "block"        # block | warn | require_confirmation | log
    min_taint_level: "external"
    owasp_ref: "LLM06"    # OWASP traceability

  - name: "shell"
    pattern: "*shell*"
    action: "block"

settings:
  enable_implicit_flow_tracking: true
  max_propagation_depth: 50
  classifier_confidence_threshold: 0.7
```

The default policy ships with **production-level rules** aligned with OWASP LLM Top 10 and OWASP ASI Top 10.

---

## 🔒 Security Posture

Erithm is a security tool — it holds itself to the standard it enforces.

### Compliance Alignment

| Standard | Coverage |
|----------|----------|
| **OWASP Top 10 for LLM Applications (v2.0)** | LLM01 (Prompt Injection), LLM06 (Excessive Agency) |
| **OWASP ASI Top 10 (Dec 2025)** | Tool misuse, agent privilege abuse, cascading failure |
| **NIST AI Risk Management Framework** | Govern / Map / Measure / Manage structure |

### Build Practices

- ✅ **No secrets in code** — API keys via environment variables only
- ✅ **Least privilege** — container runs as non-root user (Podman rootless)
- ✅ **Dependency pinning** — all deps pinned to minimum versions
- ✅ **Content redaction** — raw prompt/tool content stored in span events, not attributes
- ✅ **Audit trail** — every verdict logged as a timestamped OTel span
- ✅ **Loopback binding** — all listeners bind to `127.0.0.1`, never `0.0.0.0`
- ✅ **Safe deserialization** — `yaml.safe_load` exclusively, never `yaml.load`

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENROUTER_API_KEY` | No* | API key for LM-as-judge classifier |
| `ERITHM_VERDICT_MODE` | No | `block` \| `warn` \| `log` (default: `block`) |
| `ERITHM_CLASSIFIER_MODE` | No | `auto` \| `heuristic` \| `lm_judge` (default: `auto`) |
| `ERITHM_LOG_LEVEL` | No | Logging level (default: `INFO`) |
| `ERITHM_POLICY_PATH` | No | Path to custom policy file |

*\*Without `OPENROUTER_API_KEY`, the classifier falls back to heuristic-only mode automatically.*

---

## 📊 Benchmarks

> **Status**: Infrastructure scaffolded — numbers to be filled after AgentDojo evaluation (Week 5).

| Metric | Target | Actual |
|--------|--------|--------|
| Detection rate (AgentDojo) | >85% | _TBD_ |
| False positive rate | <15% | _TBD_ |
| Avg latency per tool call | <100ms | _TBD_ |
| vs. RTBAS (40-case set) | Comparable | _TBD_ |

---

## 🐳 Container Deployment

```bash
# Build with Podman (rootless, daemonless)
podman build -t erithm -f Containerfile .

# Run analysis
podman run --rm -v ./traces:/data:ro erithm analyze /data/trace.json

# Run with custom policy
podman run --rm \
  -v ./traces:/data:ro \
  -v ./my_policy.yaml:/app/policy.yaml:ro \
  erithm analyze /data/trace.json --policy /app/policy.yaml
```

---

## 🧪 Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=erithm --cov-report=term-missing

# Run the demo
python main.py
```

### Project Structure

```
erithm/
├── ingest/          # Stage 1: OTel span collection & normalization
├── graph/           # Stage 2: Data-flow graph construction
├── taint/           # Stage 3: Taint propagation & classification (core)
├── policy/          # YAML policy DSL loading & validation
├── verdict/         # Stage 4: Verdict engine & audit logging
├── middleware/       # Drop-in agent integration layer
├── utils/           # OTel compat layer, content redaction
└── cli.py           # Rich-formatted CLI interface
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 📚 References

- [RTBAS (2025)](https://arxiv.org/abs/) — Information-flow control for agent safety
- [AgentArmor (2025)](https://arxiv.org/abs/) — Type-system enforcement for agent traces
- [AgentFlow (2026)](https://arxiv.org/abs/) — Agent Dependency Graph IR
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP ASI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework)
- [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)

---

<div align="center">

**Built by [Ace](https://github.com/Sanyog29)** · Protecting agents from the inside out.

</div>

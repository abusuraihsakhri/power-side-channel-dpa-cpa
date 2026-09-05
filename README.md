# Power Side Channel DPA CPA

> **Domain:** Hardware Security & Side-Channel Cryptanalysis
> **Standard:** ISO/IEC 17825 Side-Channel Testing

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## What It Does

A Correlation Power Analysis (CPA) and Differential Power Analysis (DPA) side-channel attack simulation framework. Evaluates Hamming weight/distance power leakage models across AES S-Box rounds, calculates Pearson correlation coefficients, and tests resistance to countermeasures including masking, hiding, and shuffling.

---

## Key Capabilities

- **CPA/DPA Engine**: Simulates power trace generation and correlation-based key recovery attacks on AES implementations.
- **Formal Verification**: Proves correctness of Hamming weight/distance leakage models and Pearson correlation calculations against known test vectors.
- **Countermeasure Testing**: Evaluates resistance to first/second-order masking, clock jitter, noise injection, and S-Box shuffling.
- **Performance Benchmarking**: Measures convergence speed, correlation throughput, and key ranking latency.
- **Multi-Agent Supervisor**: Distributed worker architecture for task evaluation with consensus-based urgency classification.
- **Zero-PHI Outbound Guard**: Active pattern inspection blocking sensitive identifiers (SSNs, MRNs, phone numbers) from outbound data.
- **HMAC-SHA256 Audit Trail**: Cryptographically signed, tamper-evident chained audit logs with signature verification.
- **FastAPI REST API**: OpenAPI 3.1 endpoints for remote task evaluation and audit trail retrieval.

---

## Installation

```bash
pip install -e .
```

For development (with test dependencies):
```bash
pip install fastapi uvicorn pydantic pytest
```

---

## CLI Usage

### Single Task Evaluation
```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

### Batch Processing
```bash
python cli.py batch -i sample.csv -o results.csv
```

### Supervisory Chat
```bash
python cli.py chat "What is the system status?"
```

### Verify Audit Trail
```bash
python cli.py verify-audit
```

### Launch REST API Server
```bash
python cli.py serve --host 127.0.0.1 --port 8000
```

---

## REST API Endpoints

| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/health` | GET | Service health check |
| `/metrics` | GET | Operational metrics |
| `/api/audit` | POST | Submit task for evaluation |
| `/api/chat` | POST | Supervisory chat query |
| `/api/audit/logs` | GET | Retrieve and verify HMAC audit trail |

---

## Testing

Run the full test suite:
```bash
pytest -v
```

Execute the high-throughput simulation:
```bash
python simulator.py 1000
```

---

## Configuration

| Environment Variable | Description | Default |
|:---------------------|:------------|:--------|
| `AUDIT_SECRET_KEY` | Secret key for HMAC-SHA256 audit signatures | Random (ephemeral) |
| `MODEL_PROVIDER` | LLM provider (`mock`, `ollama`, `claude`, `openai`) | `mock` |

**Note:** Set `AUDIT_SECRET_KEY` to a persistent value in production. Without it, a random key is generated at startup and audit signatures will not be verifiable across restarts.

---

## Architecture

```
power-side-channel-dpa-cpa/
├── agents/                    # Multi-agent supervisor system
│   ├── api.py                 # FastAPI REST server
│   ├── base.py                # Security, PHI guard, HMAC audit trail
│   ├── models.py              # Pydantic data models
│   ├── supervisor.py          # Master orchestrator
│   ├── workers.py             # Specialized evaluation workers
│   ├── metrics.py             # Prometheus metrics exporter
│   ├── learning.py            # Bayesian calibration engine
│   ├── llm_factory.py         # LLM provider abstraction
│   └── streamer.py            # WebSocket telemetry broadcaster
├── cpa_side_channel/          # CPA/DPA core engine
│   ├── engine.py              # Domain evaluation engine
│   ├── agents.py              # Side-channel analysis agents
│   ├── models.py              # Data models
│   ├── formal_verification.py # Mathematical proof verification
│   ├── countermeasure_testing.py  # Countermeasure resistance tests
│   ├── performance_benchmark.py   # Performance benchmarks
│   ├── server.py              # Alternative FastAPI server
│   └── cli.py                 # Standalone CLI
├── tests/                     # Pytest test suite
├── web/index.html             # Operations console UI
├── cli.py                     # Main CLI entry point
├── simulator.py               # High-throughput simulation
├── enrichment.py              # Enrichment feature suite
├── Dockerfile                 # Container build
└── docker-compose.yml         # Container orchestration
```

---

## Container Deployment

```bash
docker build -t power-side-channel-dpa-cpa .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY=your-secret-key power-side-channel-dpa-cpa
```

Or with Docker Compose:
```bash
docker-compose up -d
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

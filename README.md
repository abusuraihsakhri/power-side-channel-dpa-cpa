# Power Side Channel DPA CPA

A Python project for **synthetic correlation power analysis (CPA) benchmarking** and **threshold-based audit demonstrations**. Its two analysis paths are separate: `cpa_side_channel/` contains synthetic AES S-Box leakage, correlation and countermeasure experiments; `agents/` contains a multi-worker rule evaluator with a FastAPI endpoint and an in-memory HMAC audit trail.

**Scope:** The included power traces are simulated, not oscilloscope measurements. The rule-based evaluation is not an implementation of DPA key recovery. The verification module checks supplied examples and arithmetic; its outputs are not mathematical proofs of resistance or certification against ISO/IEC 17825.

## Browser demonstration

Open `web/index.html` directly to run the **local audit sandbox**. It reproduces the Python worker thresholds without uploading data or inventing signatures. Alternatively, start the API and open `http://127.0.0.1:8000/app/` to use the same page in connected mode. The browser demonstration uses JavaScript, not Python or Pyodide.

The local interface does not perform CPA or DPA; use the Python benchmark modules for synthetic CPA experiments. The API is not authenticated and must not be exposed to untrusted networks without an authentication and authorization layer.

## Installation

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[test]"
python -m pytest -v
```

On Windows, activate with `.venv\Scripts\activate`.

## Use

Run the primary supervisor and batch-processing CLI from the repository root:

```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
python cli.py batch -i sample.csv -o results.csv
python cli.py verify-audit
python cli.py serve --host 127.0.0.1 --port 8000
```

The installed `power-side-channel-dpa-cpa` command invokes the separate `cpa_side_channel.cli` evaluator (it does not expose `verify-audit`). CSV flag values accept `true/false`, `yes/no` and `1/0`; invalid strings are rejected.

Run the synthetic CPA benchmarks through `cpa_side_channel.performance_benchmark.PerformanceBenchmarkEngine`, or run the standalone load simulator with `python simulator.py 100`.

## API

With the server running, see `/docs` for the interactive OpenAPI reference. Routes include `GET /health`, `GET /metrics`, `POST /api/audit`, `POST /api/chat` and `GET /api/audit/logs`. The audit trail is held in process memory, **not persisted across restarts**. A configured signing key allows HMAC signature consistency only for retained audit data. The PHI pattern guard is limited and does not establish HIPAA de-identification compliance.

## Containers and secrets

Copy `.env.example` to `.env` and set a unique, persistent `AUDIT_SECRET_KEY` generated using a cryptographically secure random generator, for example:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
docker compose up --build
```

Compose rejects an unset signing key. By default it publishes port 8000 only on `127.0.0.1`. Never commit a real `.env` or reuse the previously committed sample signing key.

## Testing and deployment

```bash
python -m compileall -q agents cpa_side_channel cli.py simulator.py enrichment.py
node --check web/app.js
python -m pytest -v
```

GitHub Actions runs Python tests on 3.10–3.12 and a separate workflow publishes only the static `web/` directory to GitHub Pages when that workflow is enabled. Server-side Python is not hosted on Pages. Browser support: current Chrome, Firefox, Safari and Edge with JavaScript enabled.

## License

MIT. See [LICENSE](LICENSE).

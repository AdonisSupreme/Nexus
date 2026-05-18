# SentinelOps AI

SentinelOps AI is a backend-first operational intelligence service for ICT operations. It normalizes mixed SOP formats into a single evidence model, builds a hybrid retrieval index, and uses Mistral for grounded operational responses when configured.

## Key capabilities

- Canonical SOP normalization across legacy A-F YAML and under-development SOP-E structures
- Hybrid retrieval with lexical BM25, local embeddings, and reranking
- Human-in-the-loop operational answers with citations, confidence, and escalation warnings
- Knowledge validation, ingest, reindex, and alignment reporting endpoints
- Health, diagnostics, cache, provider, and metrics endpoints

## Run locally

### Windows quick start

1. Create and activate a Python 3.11 virtual environment.

```powershell
cd C:\Users\ashumba\Documents\Sentinel\sentinelops-ai
py -3.11 -m venv sentinelai
.\sentinelai\Scripts\Activate.ps1
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

3. Populate `.env`.

- Set `MISTRAL_API_KEY` if you want live completions and classifiers.
- Set `ADMIN_API_TOKEN` if you want to use protected admin and diagnostics endpoints.
- Set `DATABASE_URL` to the same SentinelOps Postgres database used by `SentinelOps-beta`.
- Set `SECRET_KEY` and `ALGORITHM` to match `SentinelOps-beta` so Nexus can validate frontend sessions.
- Set `NEXUS_AGENT_API_TOKEN` for lightweight service collectors that post heartbeats, probe reports, and diagnostics.
- Keep `NEXUS_REQUIRE_DATABASE=true` and `NEXUS_ALLOW_LOCAL_STATE=false` for normal runtime.
- Leave `EMBEDDING_BACKEND=auto` for normal runtime. Tests override this automatically.

4. Start the API.

```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8010 --reload
```

5. Verify health.

```powershell
Invoke-RestMethod http://127.0.0.1:8010/health
Invoke-RestMethod http://127.0.0.1:8010/health/readiness
Invoke-RestMethod http://127.0.0.1:8010/health/liveness
```

### Git Bash quick start

```bash
cd ~/Documents/Sentinel/sentinelops-ai
py -3.11 -m venv sentinelai
source sentinelai/Scripts/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8010 --reload
```

## Sentinel Nexus database alignment

Sentinel Nexus is database-backed in normal runtime. The local `data\nexus_state.json` file is migration input only.

1. Apply the Nexus migration to the SentinelOps database from the main backend migration folder.

```powershell
cd C:\Users\ashumba\Documents\Sentinel\SentinelOps-beta
psql "$env:DATABASE_URL" -f .\app\db\migrations\2026_04_add_sentinel_nexus.sql
```

2. Configure `sentinelops-ai\.env` with the same database and auth settings.

```dotenv
DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/DATABASE
SECRET_KEY=the-same-secret-used-by-SentinelOps-beta
ALGORITHM=HS256
NEXUS_REQUIRE_DATABASE=true
NEXUS_ALLOW_LOCAL_STATE=false
NEXUS_REQUIRE_AGENT_AUTH=true
NEXUS_AGENT_API_TOKEN=generate-a-long-random-collector-token
```

`POSTGRES_DSN` is still accepted temporarily as a backward-compatible alias, but `DATABASE_URL` is the primary setting.

3. If you have existing local Nexus state, validate it first.

```powershell
cd C:\Users\ashumba\Documents\Sentinel\sentinelops-ai
python .\scripts\migrate_nexus_state_to_postgres.py --dry-run
```

4. Apply the one-time migration and create a timestamped backup.

```powershell
python .\scripts\migrate_nexus_state_to_postgres.py --apply --verify
```

5. Start Nexus on port `8010`. It will fail startup clearly if `DATABASE_URL` is missing or if the Nexus migration tables are not present.

```powershell
python -m uvicorn app.main:app --host 0.0.0.0 --port 8010 --reload
```

The health endpoint reports Nexus database readiness, SentinelOps session auth mode, schema status, local-state status, and the operational OSEMN loop: Evidence Intake, Normalization, Correlation, Prediction, and Operator Guidance.

## Ingest and inspect knowledge

1. Start the API.
2. Trigger ingest once so the normalized corpus, chunk graph, and alignment report are built.

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8010/api/v1/knowledge/ingest `
  -Headers @{ Authorization = "Bearer YOUR_ADMIN_API_TOKEN" }
```

3. Inspect the alignment report.

```powershell
Invoke-RestMethod `
  -Uri http://127.0.0.1:8010/api/v1/knowledge/alignment-report `
  -Headers @{ Authorization = "Bearer YOUR_ADMIN_API_TOKEN" }
```

## Run tests

### Standard test command

```powershell
pytest tests -q
```

The test suite is configured to avoid heavy local model initialization:

- `tests/conftest.py` forces `EMBEDDING_BACKEND=hash`
- reranking is disabled for tests
- tokenizer parallelism is disabled to avoid the Windows access-violation path you hit earlier

### If the virtualenv launcher is broken on Windows

Some Windows environments end up with a stale `sentinelai\Scripts\python.exe` or `pytest.exe` launcher even though the packages inside the environment are fine. If `pytest` fails to start, use the installed Python 3.11 interpreter directly:

```powershell
$env:PYTHONPATH='C:\Users\ashumba\Documents\Sentinel\sentinelops-ai\sentinelai\Lib\site-packages'
& 'C:\Users\ashumba\AppData\Local\Programs\Python\Python311\python.exe' -m pytest tests -q
```

That is the fallback command used to validate the current repo state.

## Main endpoints

- `POST /api/v1/query`
- `POST /api/v1/classify`
- `POST /api/v1/sops/search`
- `GET /api/v1/sops/{sop_id}`
- `GET /api/v1/sops/{sop_id}/graph`
- `POST /api/v1/knowledge/validate`
- `POST /api/v1/knowledge/ingest`
- `POST /api/v1/knowledge/reindex`
- `GET /api/v1/knowledge/jobs/{job_id}`
- `GET /api/v1/knowledge/alignment-report`
- `GET /health`
- `GET /health/readiness`
- `GET /health/liveness`

## Notes

- The current corpus is marked `verified_from_corpus` and `pending_manual_reconciliation` until the new procedure manual is exported into machine-readable form.
- If local ML dependencies are unavailable, the service falls back to deterministic hash embeddings and still returns evidence-grounded results.

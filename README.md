# BT Threat Intel

An LLM-backed active threat intelligence platform that monitors public vulnerability feeds,
correlates findings against a defined asset environment, and surfaces actionable intelligence
through an analyst chat interface and automated alerting.

Built to demonstrate threat intelligence engineering, LLM/RAG system
design, prompt injection defense, and IR-adjacent tooling.

---

## What it does

- Pulls CVE and threat data from five public feeds (NVD, CISA KEV, AlienVault OTX, ExploitDB, GitHub PoC)
- Normalizes, deduplicates, and embeds ingested data into a vector database for semantic search
- Uses Claude (claude-sonnet-4-6) to triage CVEs, map to MITRE ATT&CK TTPs, and assess exploitability
- Correlates findings against a user-defined asset inventory (`stack.yaml`) using CPE matching and LLM confirmation
- Generates LLM-backed aliases for any asset in `stack.yaml` so CVE matching works across naming variants
- Surfaces alerts via Slack webhook and CLI output for confirmed exposures
- Provides a Streamlit analyst chat interface with three-path RAG retrieval:
  - Environment queries pull directly from confirmed exposures
  - Asset-specific queries filter to confirmed exposures for that asset
  - General landscape queries run severity-filtered semantic search
- Generates IR playbooks for confirmed exposures
- Runs on a configurable schedule via APScheduler, processing only new records each run

---

## Demo

**Part 1 — Analyst Chat Interface**

https://github.com/EvanGoldConn/bt-threat-intel/raw/main/docs/demo-chat-interface.mp4

**Part 2 — Ingestion/Correlation Slack Alerts**

https://github.com/EvanGoldConn/bt-threat-intel/raw/main/docs/demo-slack-alert.mp4

## Architecture

```
Public Feeds (NVD, CISA KEV, OTX, ExploitDB, GitHub PoC)
    |
    v
Ingestion Pipeline      src/ingestion/pipeline.py
    Fetch, normalize, deduplicate, store, embed
    |
    +-> ThreatStore      src/ingestion/store.py
    |       PostgreSQL read/write, sanitization, correlated_at tracking
    |
    +-> Embeddings       src/ingestion/embeddings.py
            Ollama (nomic-embed-text) -> pgvector (768-dim)
            Confirmed exposures re-embedded with enriched text

Asset Correlator        src/correlator/correlator.py
    CPE matching + LLM confirmation against stack.yaml
    Alias-aware keyword fallback via src/ingestion/assets.py
    LLM-generated aliases cached in config/alias_cache.yaml
    Writes confirmed exposures to exposure_results table

Analysis Layer          src/analysis/
    CveTriage, TtpMapper, PlaybookGenerator
    All external data wrapped in XML delimiter tags (prompt injection defense)

Alerting                src/alerting/alerter.py
    Slack Block Kit + rich CLI panels

Analyst Chat            src/chat/pipeline.py + ui/app.py
    Three-path RAG: environment / asset-specific / general landscape
    Retrieved chunks wrapped in XML delimiter tags (RAG poisoning defense)

Scheduler               scripts/scheduler.py
    APScheduler BlockingScheduler, full pipeline on configurable interval
    scripts/run_pipeline.py for manual runs
    scripts/recorrelate.py for stack.yaml change re-scans
```

---

## Tech stack

| Layer | Tool |
|---|---|
| Language | Python 3.13 |
| LLM reasoning | Claude claude-sonnet-4-6 via Anthropic API |
| Embeddings | nomic-embed-text via Ollama (local) |
| Vector store | pgvector (PostgreSQL 16 extension) |
| Job scheduling | APScheduler |
| UI | Streamlit |
| Containerization | Docker Compose (PostgreSQL only) |

---

## Project structure

```
bt-threat-intel/
├── src/
│   ├── ingestion/
│   │   ├── feeds/            # NVD, CISA KEV, OTX, ExploitDB, GitHub PoC
│   │   ├── pipeline.py       # Orchestration: fetch, dedup, store, embed, analyze
│   │   ├── store.py          # PostgreSQL read/write layer
│   │   ├── embeddings.py     # Ollama embedding calls, pgvector storage
│   │   ├── assets.py         # Shared asset utility, alias detection
│   │   └── alias_generator.py # LLM-backed alias generation with caching
│   ├── analysis/
│   │   ├── client.py         # Anthropic SDK wrapper, singleton
│   │   ├── triage.py         # CVE exploitability assessment
│   │   ├── ttp_mapper.py     # MITRE ATT&CK TTP mapping
│   │   └── playbook.py       # IR playbook generation
│   ├── correlator/
│   │   └── correlator.py     # Two-stage CPE + LLM asset correlation
│   ├── alerting/
│   │   └── alerter.py        # Slack webhook and CLI alerts
│   └── chat/
│       └── pipeline.py       # Three-path RAG pipeline
├── ui/
│   └── app.py                # Streamlit analyst chat UI
├── config/
│   ├── feeds.yaml            # Feed enable/disable and parameters
│   ├── stack.yaml            # Asset inventory
│   └── alias_cache.yaml      # LLM-generated asset aliases (auto-populated)
├── scripts/
│   ├── run_pipeline.py       # Full pipeline: ingest + correlate + reembed
│   ├── run_ingestion.py      # Ingestion only
│   ├── run_correlator.py     # Correlation only
│   ├── reembed_exposures.py  # Re-embed confirmed exposures with enriched text
│   ├── recorrelate.py        # Force full re-correlation after stack.yaml changes
│   ├── scheduler.py          # APScheduler scheduled pipeline runner
│   └── init_db.sql           # PostgreSQL schema
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Setup

### Requirements

- Python 3.13
- Docker and Docker Compose
- Ollama installed locally with `nomic-embed-text` pulled
- Anthropic API key
- NVD API key (free, from nvd.nist.gov)
- AlienVault OTX API key (free, from otx.alienvault.com)
- Slack webhook URL (optional)

### Installation

```bash
git clone https://github.com/yourusername/bt-threat-intel.git
cd bt-threat-intel

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Fill in API keys in .env

ollama pull nomic-embed-text

docker compose up -d db

# Initialize the database schema
docker exec -i bt_threat_intel_db psql -U btuser -d bt_threat_intel < scripts/init_db.sql
```

### Configuration

Edit `config/stack.yaml` to define your asset inventory before running the correlator.
See `config/stack.example.yaml` for format. Add any software your environment runs.
Aliases for new assets are generated automatically on the first correlator run.

---

## Usage

### Run everything (recommended)

```bash
# Bring the full system current: ingest, correlate, reembed
python scripts/run_pipeline.py
```

### Run on a schedule

```bash
# Start the scheduler (runs full pipeline every INGEST_SCHEDULE_HOURS hours)
python scripts/scheduler.py
```

### Launch the analyst chat interface

```bash
streamlit run ui/app.py
```

### After updating stack.yaml

```bash
# Preview scope of re-correlation
python scripts/recorrelate.py --dry-run

# Clear correlated_at and re-queue all records
python scripts/recorrelate.py

# Re-correlate against updated stack
python scripts/run_pipeline.py
```

### Manual steps

```bash
python scripts/run_ingestion.py      # ingestion only
python scripts/run_correlator.py     # correlation only (top 500 by CVSS)
python scripts/reembed_exposures.py  # re-embed confirmed exposures only
```

---

## Possible future additions

- REST API layer (FastAPI): expose threat queries, chat, and correlation triggers as HTTP endpoints
- Dependency scanner: auto-populate `stack.yaml` from `requirements.txt`, `package.json`, `go.mod`
- Hybrid retrieval in chat pipeline: combine semantic search with SQL filters for temporal queries
- Conversation history in chat UI for multi-turn analyst sessions
- Sigma rule suggestions per confirmed CVE exposure
- Live network scan integration (from separate recon project)

---
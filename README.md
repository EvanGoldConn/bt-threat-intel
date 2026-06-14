# BT Threat Intel

An LLM-backed active threat intelligence platform that monitors public vulnerability feeds,
correlates findings against a defined asset environment, and surfaces actionable intelligence
through an analyst chat interface and automated alerting.

Built to create a practical application combining LLM/RAG pipelines, threat intelligence concepts, and IR tooling.

---

## What it does

- Pulls CVE and threat data from public feeds (NVD, CISA KEV, AlienVault OTX, ExploitDB)
- Normalizes and embeds ingested data into a vector database for semantic search
- Uses Claude (claude-sonnet-4-6) to triage CVEs, map to MITRE ATT&CK TTPs, and assess exploitability
- Correlates findings against a user-defined asset inventory (stack.yaml)
- Surfaces alerts via Slack webhook and CLI output
- Provides a Streamlit-based analyst chat interface for natural language queries against the live intel store
- Generates IR playbooks for confirmed exposures (v1 scope: basic structured output)

---

## Architecture

```
Ingestion layer     ->  NVD / CISA KEV / AlienVault OTX / ExploitDB / GitHub PoC watch
Normalize + embed   ->  pgvector (PostgreSQL) via nomic-embed-text (Ollama, local)
LLM analysis core   ->  Claude API (triage, TTP mapping, report generation)
Asset correlator    ->  stack.yaml cross-referenced against incoming CVEs
Alerting            ->  Slack webhook + CLI
Analyst interface   ->  Streamlit chat UI backed by RAG pipeline
```

---

## Tech stack

| Layer | Tool |
|---|---|
| Language | Python 3.11 |
| LLM (reasoning) | Claude claude-sonnet-4-6 via Anthropic API |
| Embeddings | nomic-embed-text via Ollama (local) |
| Vector store | pgvector (PostgreSQL extension) |
| Job scheduling | APScheduler |
| API layer | FastAPI |
| UI | Streamlit |
| Containerization | Docker Compose |
| Environment | Python venv on external drive |

---

## Project structure

```
bt-threat-intel/
├── src/
│   ├── ingestion/        # Feed pullers and normalization
│   ├── analysis/         # LLM triage, TTP mapping, report generation
│   ├── correlator/       # Asset inventory cross-referencing
│   ├── alerting/         # Slack webhook and CLI output
│   ├── chat/             # RAG pipeline for analyst chat interface
│   └── api/              # FastAPI backend
├── ui/                   # Streamlit app
├── config/               # stack.yaml asset inventory, feed config
├── data/
│   ├── raw/              # Raw feed output (gitignored)
│   └── processed/        # Normalized records (gitignored)
├── docs/                 # Additional documentation
├── tests/
│   ├── unit/
│   └── integration/
├── scripts/              # Setup and utility scripts
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── .env.example
```

---

## Setup

### Requirements

- Python 3.11+
- Docker and Docker Compose
- Ollama installed locally (for embeddings)
- Anthropic API key
- Slack webhook URL (optional, for alert notifications)

### Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/bt-threat-intel.git
cd bt-threat-intel

# Create and activate virtual environment on external drive
python3 -m venv /Volumes/UTM_DRIVE/bt-threat-intel-venv
source /Volumes/UTM_DRIVE/bt-threat-intel-venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and fill in environment variables
cp .env.example .env

# Pull the embedding model via Ollama
ollama pull nomic-embed-text

# Start the database
docker compose up -d db

# Run the ingestion pipeline manually to populate initial data
python scripts/run_ingestion.py
```

### Configuration

Edit config/stack.yaml to define your asset environment before running the correlator.
See config/stack.example.yaml for format.

---

## Usage

```bash
# Start all services
docker compose up

# Run the Streamlit analyst interface
streamlit run ui/app.py

# Trigger a manual ingestion run
python scripts/run_ingestion.py

# Run the correlator against current intel
python scripts/run_correlator.py
```

---

## Planned

- SOAR-style alert output formatting
- Live network scan integration (from separate recon project)
- Expanded IR playbook generation
- Sigma rule suggestions per CVE

---

## Disclaimer

This project is built for educational and portfolio purposes. It pulls from public feeds only.
Do not use against systems you do not own or have explicit permission to assess.

---

## Author

Built by [your name] as part of a cybersecurity career transition portfolio.
Companion projects: network recon tool, LLM injection research.

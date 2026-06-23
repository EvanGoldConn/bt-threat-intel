# BT Threat Intel - Architecture Reference

Personal reference document. Covers how the system is structured, how data moves through it, why key decisions were made, and where to look when something breaks.

---

## High-Level Data Flow

```
Public Feeds (NVD, CISA KEV, OTX, ExploitDB, GitHub PoC)
    │
    ▼
IngestionPipeline.run()          src/ingestion/pipeline.py
    │
    ├── fetch() on each feed      src/ingestion/feeds/*.py
    │       Each feed inherits BaseFeed, implements fetch() and normalize()
    │       fetch() handles HTTP, pagination, error handling
    │       normalize() maps one raw API item to a ThreatRecord Pydantic model
    │
    ├── _deduplicate()
    │       Deduplicates by cve_id, keeps most recent modified_at
    │       Records with no cve_id pass through untouched (OTX pulses, GitHub repos)
    │
    ├── _store_records()
    │       Calls ThreatStore.upsert_record() for each record
    │       Returns (ThreatRecord, threat_id) tuples
    │
    ├── embeddings.store_embedding()
    │       build_embedding_text(): "CVE-ID | severity | title | description"
    │       Confirmed exposures embedded with enriched text including asset name
    │       and CISA KEV ransomware signal if present
    │       Sends to Ollama (nomic-embed-text, local), stores 768-dim vector
    │
    └── _analyze_new_records()
            Gated: skips records with no cve_id, no description, or existing ttp_mappings row
            Capped: ANALYSIS_BATCH_LIMIT = 50 records per run
            │
            ├── CveTriage.triage()        src/analysis/triage.py
            │       Stored as triage_* keys inside raw_data JSONB
            │
            └── TtpMapper.map()           src/analysis/ttp_mapper.py
                    Stored as rows in ttp_mappings table


Asset Correlator                 src/correlator/correlator.py
    │
    ├── get_all_assets()
    │       Delegates to src/ingestion/assets.py
    │       Flattens all categories from stack.yaml into a list of asset dicts
    │
    ├── _extract_candidates()
    │       Stage 1 pre-filter: fast, no LLM cost
    │       CPE string parsing from raw_data if present
    │       Falls back to alias-aware keyword matching via get_all_search_terms()
    │       Aliases sourced from ASSET_ALIASES (static) or alias_generator (LLM-cached)
    │       MIN_KEYWORD_TERM_LENGTH = 4 guard prevents short-term false positives
    │
    └── _llm_confirm()
            Stage 2: LLM call only for assets that passed pre-filter
            Wraps CVE and asset data in XML delimiter tags (prompt injection defense)
            Returns ExposureResult with is_exposed bool and rationale string
            Confirmed exposures written to exposure_results table via store.save_exposure()
            correlated_at timestamp set on each processed record via store.mark_correlated()


Alias System                     src/ingestion/assets.py + src/ingestion/alias_generator.py
    │
    ├── ASSET_ALIASES (static overrides)
    │       Curated map of known CVE description variants per asset
    │       Takes precedence, no LLM call made
    │
    └── alias_generator.generate_aliases()
            For assets not in ASSET_ALIASES, calls Claude to generate aliases
            Sanitizes asset name input before prompt construction
            Validates LLM response: must be list of strings, each under 50 chars,
            matching ^[a-z0-9 .\-/_@]+$, max 15 entries
            Caches result to config/alias_cache.yaml (write-once per asset)
            Cache validated on load, malformed entries dropped
            Falls back to asset name alone on any failure


Analyst Chat                     src/chat/pipeline.py + ui/app.py
    │
    ├── _sanitize_query()
    │       Strips null bytes and XML tags from user input
    │
    ├── _classify_intent()
    │       Checks for environment intent phrases (our environment, our stack, etc.)
    │       Returns 'environment' or 'general'
    │
    ├── detect_asset_in_query()
    │       Checks query for asset names/aliases from stack.yaml
    │       Only routes to asset path if confirmed exposures exist for that asset
    │
    └── Three retrieval paths:
            environment  -> get_confirmed_exposures() all confirmed, ordered by CVSS
            asset        -> get_confirmed_exposures(asset_name=X) for specific asset
            general      -> severity_filter=['critical','high'] similarity search


Pipeline Scripts
    │
    ├── scripts/run_pipeline.py
    │       Full pipeline in sequence: ingest -> correlate -> reembed
    │       Uses get_uncorrelated_records() to process only new records
    │       Skips re-embedding if no new exposures found
    │
    ├── scripts/scheduler.py
    │       APScheduler BlockingScheduler
    │       max_instances=1, coalesce=True (no overlapping runs)
    │       Error listener logs failures without crashing
    │       Runs pipeline_job() on INGEST_SCHEDULE_HOURS interval
    │
    └── scripts/recorrelate.py
            Clears correlated_at on all critical/high records
            --dry-run flag previews scope without changes
            Use after significant stack.yaml changes
            Run run_pipeline.py after to re-correlate
```

---

## Layer by Layer

### Feeds (src/ingestion/feeds/)

All five feeds inherit `BaseFeed`. The contract: `fetch()` returns `List[ThreatRecord]`, `normalize()` maps one raw item to a `ThreatRecord`.

| Feed | Source | Notes |
|---|---|---|
| NvdFeed | NVD REST API v2 | Paginated, rate limited (0.6s delay), CVSS fallback chain: V31 > V30 > V2 |
| CisaKevFeed | CISA KEV JSON | Single request, no pagination, severity hardcoded to "high", captures known_ransomware_use |
| OtxFeed | AlienVault OTX pulses | Cursor-based pagination, one ThreatRecord per CVE indicator per pulse |
| ExploitDbFeed | RSS via feedparser | CVE ID extracted via regex from title/summary |
| GithubPocFeed | GitHub repo search API | CVE ID extracted via regex from repo name/description |

Config for each feed lives in `config/feeds.yaml` at the root level (no `feeds:` wrapper key).

### Models (src/ingestion/models.py)

`ThreatRecord` - normalized unit of data. Key fields: `cve_id`, `source`, `description`, `cvss_score`, `severity`, `published_at`, `reference_urls`, `raw_data`.

`ExposureResult` - correlator output. Links `threat_id` to `asset_name`, `asset_version`, `is_exposed`, `rationale`.

`IRPlaybook` - playbook output. Contains `steps: List[str]`, `priority`, `cve_id`, `threat_id`, `generated_at` (timezone-aware UTC).

### Storage (src/ingestion/store.py)

`ThreatStore` is the only class that talks to PostgreSQL. All queries are parameterized.

`upsert_record()` uses `ON CONFLICT (cve_id) DO UPDATE`.

`_sanitize_text()` runs on `title` and `description`. Strips null bytes and Unicode control characters, truncates to `MAX_FIELD_LENGTH = 8000`.

`get_uncorrelated_records()` returns critical/high records where `correlated_at IS NULL`. No limit — processes all new records.

`mark_correlated(threat_id)` stamps `correlated_at = NOW()` after processing, regardless of whether an exposure was found.

`get_confirmed_exposures(asset_name=None)` joins `exposure_results` to `threat_records`, filters `is_exposed = TRUE`, ordered by CVSS descending. Optional `asset_name` filter for asset-specific queries.

`save_exposure()` writes to `exposure_results` with `ON CONFLICT DO NOTHING` (unique constraint on `threat_id, asset_name`).

### Embeddings (src/ingestion/embeddings.py)

Ollama API (v0.22.0+): endpoint `/api/embed`, request field `input`, response field `embeddings[0]`.

`build_embedding_text(record, confirmed_exposure=False, asset_name=None)`:
- Base: `"CVE-ID | severity | title | description"`
- With confirmed_exposure: prepends `"CONFIRMED EXPOSURE: <asset_name> | ..."`
- With CISA KEV ransomware signal: inserts `"KNOWN RANSOMWARE USE"` after severity

`similarity_search(query_embedding, limit, severity_filter=None)`: optional severity pre-filter restricts corpus before ranking by cosine distance.

### Analysis Client (src/analysis/client.py)

Singleton via `get_analysis_client()`. `complete_json()` strips markdown fences, calls `json.loads()`, returns parsed dict. Raises `ValueError` on parse failure.

### Prompt Security

All external data wrapped in XML delimiter tags before LLM calls. System prompts instruct model to treat tagged content as untrusted. Applied in: triage, TTP mapper, playbook generator, correlator LLM confirmation, chat pipeline retrieved chunks.

Tag names: `<cve_data>` in triage/TTP mapper/correlator, `<exposure_data>` in playbook generator, `<threat_context>` in chat pipeline.

### Correlator (src/correlator/correlator.py)

Two-stage matching. Stage 1: CPE parse or alias-aware keyword match (free). Stage 2: LLM confirmation (costs API call). Only Stage 1 candidates go to Stage 2.

Alias system resolves naming variants: "chromium" matches "chrome", "github actions" matches "github-actions", "reactjs" matches "react". Short terms under 4 characters skipped to prevent false positives.

### Chat Pipeline (src/chat/pipeline.py)

Three retrieval paths based on intent classification:

1. **Environment path**: `ENVIRONMENT_INTENT_PHRASES` match → `get_confirmed_exposures()` → all confirmed exposures ordered by CVSS
2. **Asset path**: asset name detected in query AND confirmed exposures exist for that asset → `get_confirmed_exposures(asset_name=X)`
3. **General path**: severity-filtered similarity search (`critical`, `high` only)

Falls back gracefully: if environment path returns nothing, falls to general. If asset path finds no confirmed exposures, falls to general.

---

## Database Schema

```sql
threat_records      id, cve_id (UNIQUE), source, title, description,
                    cvss_score, cvss_vector, severity, published_at,
                    modified_at, reference_urls (JSONB), raw_data (JSONB),
                    created_at, correlated_at

                    raw_data also stores triage results as triage_* keys

threat_embeddings   id, threat_id (UNIQUE FK), embedding (vector(768)), embedded_at

ttp_mappings        id, threat_id (FK), tactic, technique_id,
                    technique_name, confidence, mapped_at

exposure_results    id, threat_id (FK), asset_name, asset_version,
                    is_exposed, rationale, assessed_at
                    UNIQUE (threat_id, asset_name)

ir_playbooks        id, threat_id (FK), content, generated_at
```

`reference_urls` named deliberately to avoid PostgreSQL reserved word `references`.

---

## Key Design Decisions

**correlated_at instead of a separate tracking table:** single nullable column on `threat_records` is simpler to query and index. NULL means unprocessed, timestamp means done. `recorrelate.py` resets to NULL when stack changes.

**exposure_results unique constraint on (threat_id, asset_name):** prevents duplicate exposures from repeated correlator runs. `ON CONFLICT DO NOTHING` in `save_exposure()` relies on this constraint existing.

**LLM alias generation cached write-once:** aliases are generated once per asset per category and never regenerated unless the cache is manually cleared. Prevents repeated LLM calls on every correlator run and limits blast radius of any malformed response.

**Alias validation rejects entire response on any bad entry:** partial acceptance of LLM alias output creates subtle matching bugs. All-or-nothing validation with fallback to asset name alone is safer and predictable.

**Three-path chat retrieval instead of one:** pure cosine similarity against 4,400+ records returns irrelevant results. Environment path bypasses similarity search entirely for confirmed exposure queries. Asset path narrows to confirmed exposures for a specific asset. General path limits corpus to critical/high severity only.

**detect_asset_in_query uses use_llm=False at query time:** LLM alias generation happens at correlator run time and is cached. Live chat queries should never trigger LLM calls for alias generation — only cache reads.

**Why raw_data for triage results instead of new columns:** avoids schema migration. Queryable via JSONB operators if needed.

**Why complete_json() returns a parsed dict:** originally returned a raw string. One caller (correlator) forgot to parse, causing AttributeError. Moved json.loads() into complete_json() so the contract is unambiguous.

---

## Operational Runbook

**Normal operation (automated):**
```bash
python scripts/scheduler.py    # runs full pipeline every INGEST_SCHEDULE_HOURS
```

**Manual immediate update:**
```bash
python scripts/run_pipeline.py
```

**After stack.yaml changes:**
```bash
python scripts/recorrelate.py --dry-run   # preview scope
python scripts/recorrelate.py             # clear correlated_at
python scripts/run_pipeline.py            # re-correlate against updated stack
```

**After build_embedding_text() changes:**
```bash
python scripts/reembed_exposures.py       # re-embed confirmed exposures with new text
```

---

## Where Things Break

**Ingestion fails for one feed:** each feed is wrapped in try/except in pipeline.run(). One failure logs and continues. Check logs for the feed class name.

**Embeddings fail:** Ollama must be running. Check `ollama serve`, confirm `nomic-embed-text` is pulled. Endpoint is `/api/embed`, request field `input`, response field `embeddings[0]`.

**Correlator returns 0 exposures:** if `get_uncorrelated_records()` returns empty, all records have `correlated_at` set. Run `recorrelate.py` to reset. Also check that `correlated_at` column exists on `threat_records`.

**exposure_results stays empty after correlator run:** check that `store.save_exposure()` is being called and that `ExposureResult` is imported in `store.py`. The unique constraint `exposure_results_threat_asset_unique` must exist or `ON CONFLICT DO NOTHING` will insert duplicates.

**Chat returns irrelevant results:** check which retrieval path fired. Add `logger.info` after `_classify_intent()` and `detect_asset_in_query()` to see routing. If environment queries miss, check `ENVIRONMENT_INTENT_PHRASES`. If asset queries miss, check `exposure_results` is populated and `detect_asset_in_query()` is matching the asset name.

**Alias cache not populated:** cache file is `config/alias_cache.yaml` relative to project root. Run the correlator from the project root directory. Check that assets not in `ASSET_ALIASES` are triggering `alias_generator.generate_aliases()` and that `get_analysis_client()` is returning a real client with a valid API key.

**Slack alerts return 404:** `SLACK_WEBHOOK_URL` in `.env` is a placeholder or expired. Regenerate via Slack app settings.

**OTX times out mid-pagination:** expected. Error handling returns records collected before timeout.

---

## Environment Variables

```
ANTHROPIC_API_KEY         Claude API key
NVD_API_KEY               NVD REST API key
ALIENVAULT_OTX_API_KEY    AlienVault OTX API key
POSTGRES_HOST             default: localhost
POSTGRES_PORT             default: 5432
POSTGRES_DB               bt_threat_intel
POSTGRES_USER             btuser
POSTGRES_PASSWORD
OLLAMA_BASE_URL           default: http://localhost:11434
EMBEDDING_MODEL           default: nomic-embed-text
SLACK_WEBHOOK_URL
LOG_LEVEL                 default: INFO
INGEST_SCHEDULE_HOURS     default: 6
CVE_LOOKBACK_DAYS         default: 7
```

---

## What Is Built and Confirmed Working

- All five ingestion feeds
- Deduplication, PostgreSQL storage, sanitization
- pgvector embeddings with enriched text for confirmed exposures
- LLM triage, TTP mapping, playbook generation
- Automated analysis on new records (ANALYSIS_BATCH_LIMIT = 50)
- Asset correlator: two-stage CPE/alias-keyword + LLM confirmation
- LLM-backed alias generation with caching and injection defense
- correlated_at tracking for efficient incremental correlator runs
- CLI and Slack alerting (alert_exposure, alert_high_severity)
- Three-path RAG chat pipeline with XML delimiter poisoning defense
- Streamlit analyst chat UI
- Full pipeline runner (run_pipeline.py)
- APScheduler scheduler (scheduler.py)
- Force re-correlation script (recorrelate.py)

## Possible Future Additions

- REST API layer: GET /threats, POST /chat, GET /exposures, POST /correlate
- Dependency scanner to auto-populate stack.yaml
- Hybrid retrieval combining similarity search with SQL date/severity filters
- Conversation history in chat UI for multi-turn sessions
- Sigma rule suggestions per confirmed exposure
- Live network scan integration
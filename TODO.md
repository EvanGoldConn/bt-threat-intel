# TODO

## Phase 1: Ingestion Pipeline
- [x] `nvd_feed.py` - implement `fetch()` and `normalize()`
- [x] `cisa_kev_feed.py` - implement `fetch()` and `normalize()`
- [x] `otx_feed.py` - implement `fetch()` and `normalize()`
- [x] `exploitdb_feed.py` - implement `fetch()` and `normalize()`
- [x] `github_poc_feed.py` - implement `fetch()` and `normalize()`
- [x] `store.py` - implement `upsert_record()`, `get_record_by_cve()`, `get_recent_records()`, `record_exists()`
- [x] `pipeline.py` - implement `_deduplicate()`
- [x] `embeddings.py` - implement `embed_text()`, `store_embedding()`, `similarity_search()`
- [x] End to end test: run `scripts/run_ingestion.py` and confirm records land in the database

## Phase 2: LLM Analysis
- [x] `analysis/triage.py` - implement `triage()`
- [x] `analysis/ttp_mapper.py` - implement `map()`
- [x] `analysis/playbook.py` - implement `generate()`
- [x] End to end test: run triage and TTP mapping against a known CVE and review output

## Phase 3: Asset Correlator
- [x] Copy `config/stack.example.yaml` to `config/stack.yaml` and fill in real environment
- [x] `correlator/correlator.py` - implement `get_all_assets()` and `correlate()`
- [x] `alerting/alerter.py` - implement `_cli_alert()` and `_slack_alert()`
- [x] End to end test: run `scripts/run_correlator.py` and confirm exposures are detected

## Phase 4: Alerting
- [x] `alerting/alerter.py` - implement `_cli_alert()`
- [x] `alerting/alerter.py` - implement `_slack_alert()`
- [x] `alerting/alerter.py` - implement `alert_high_severity()`
- [x] Set up Slack workspace and configure webhook URL in `.env`
- [x] End to end test: confirm Slack alert fires with real webhook

## Phase 5: Analyst Chat Interface
- [x] `chat/pipeline.py` - implement `_format_context()`
- [x] `chat/pipeline.py` - implement `query()` with XML delimiter wrapping on retrieved chunks (RAG poisoning defense)
- [x] `chat/pipeline.py` - three-path retrieval: environment, asset-specific, general landscape
- [x] `ingestion/assets.py` - shared asset utility module with alias-aware detection
- [x] `ingestion/alias_generator.py` - LLM-backed alias generation with caching and injection defenses
- [x] `ui/app.py` - test Streamlit UI end to end
- [x] End to end test: ask a question about a known ingested CVE and verify grounded response

## Phase 6: Scheduler
- [x] `scripts/run_pipeline.py` - single command to run ingestion, correlation, and re-embedding in sequence
- [x] `scripts/scheduler.py` - APScheduler BlockingScheduler running full pipeline on configurable interval
- [x] `scripts/recorrelate.py` - manual re-correlation trigger after stack.yaml changes
- [x] `store.py` - `get_uncorrelated_records()` and `mark_correlated()` for efficient incremental runs
- [x] `threat_records.correlated_at` column added to DB and init_db.sql
- [x] End to end test: full pipeline run confirmed, 76 confirmed exposures, 0 failures

## Phase 7: Polish
- [ ] Add unit tests for feed normalization
- [ ] Add unit tests for correlator matching logic
- [ ] Add integration test for full ingestion to alert pipeline
- [ ] Review and clean up all TODO comments in source files
- [ ] Update README with final usage instructions and demo GIF
- [ ] Final git review and push

## Future Improvements

### Dependency Scanner (high value, build next)
- [ ] Build `scripts/scan_dependencies.py` that auto-populates `stack.yaml` libraries section
- [ ] Parse `requirements.txt` and `pip freeze` output for Python dependencies
- [ ] Parse `package.json` and `package-lock.json` for Node dependencies
- [ ] Parse `go.mod` for Go dependencies
- [ ] Parse `Gemfile.lock` for Ruby dependencies
- [ ] Run scan as a pre-step before correlator to keep stack.yaml current automatically
- [ ] Flag transitive dependencies separately from direct dependencies in stack.yaml
- [ ] Auto-detect installed tool versions (Chrome, OpenSSL, curl, git) from the host system

### Conversation History (high value, build next)
- [ ] Store message history in Streamlit session state
- [ ] Pass full conversation history to `ChatPipeline.query()` on each turn
- [ ] Support follow-up queries: "tell me more about the second one", "generate a playbook for that CVE"
- [ ] Cap history length to avoid context window overflow (rolling window of last N turns)

### REST API Layer (enables enterprise integration)
- [ ] `api/routes/threats.py` - GET /threats with severity and date filters
- [ ] `api/routes/chat.py` - POST /chat endpoint wrapping `ChatPipeline.query()`
- [ ] `api/routes/exposures.py` - GET /exposures returning confirmed exposure_results rows
- [ ] `api/routes/correlate.py` - POST /correlate to trigger a manual correlation run
- [ ] Wire routes into `api/main.py`
- [ ] Add API key auth before any external exposure
- [ ] Add rate limiting to all endpoints
- [ ] Enable SIEM, ticketing system, and dashboard integration via REST

### Hybrid Retrieval (improves temporal queries)
- [ ] Combine similarity search with SQL filters on `published_at` and `severity`
- [ ] Support temporal queries: "what CVEs came out this week", "what's new since Monday"
- [ ] Add date range detection to `_classify_intent()` in `chat/pipeline.py`
- [ ] Add `get_recent_high_severity()` store method with date + severity filters

### Source Array Tracking (improves intelligence quality)
- [ ] Add `sources` JSONB array column to `threat_records`
- [ ] During deduplication in `pipeline.py`, accumulate all sources seen for a given CVE
- [ ] Pass source array to `CveTriage.triage()` as an additional exploitability signal
- [ ] A CVE seen in NVD + CISA KEV + OTX simultaneously is a hotter signal than NVD alone

### Sigma Rule Generation (high wow factor, immediately actionable)
- [ ] Add `src/analysis/sigma_generator.py` - generate a Sigma detection rule per confirmed exposure
- [ ] Prompt takes ThreatRecord + ExposureResult, outputs a valid Sigma YAML rule
- [ ] Call from `run_correlator.py` / `run_pipeline.py` after playbook generation
- [ ] Store generated rules in a new `sigma_rules` table or as files in `data/sigma/`
- [ ] Gives analysts something they can immediately drop into their SIEM

### Trend Analysis (turns tool from reactive to predictive)
- [ ] Track CVE volume per asset over time using `published_at` from `threat_records`
- [ ] Add `scripts/run_trends.py` that queries exposure history and surfaces anomalies
- [ ] Surface in chat: "Are there more Chrome CVEs this month than last month?"
- [ ] Add a trends endpoint to the REST API

### Multi-Environment Support (enterprise-ready)
- [ ] Support multiple `stack.yaml` files, one per environment (prod, staging, dev)
- [ ] Each environment gets its own correlation run and its own `exposure_results` partition
- [ ] Add `environment` field to `exposure_results` table
- [ ] Chat pipeline routes queries to the correct environment's exposure set

### Live Network Scan Integration
- [ ] Connect to the separate recon project to auto-populate `stack.yaml`
- [ ] Replace manual asset version entry with live scan results
- [ ] Trigger re-correlation automatically when scan results change
- [ ] Ties the two portfolio projects together into a single pipeline

### Scheduled Re-correlation on Stack Changes
- [ ] Add hash check on `stack.yaml` at scheduler startup
- [ ] If hash has changed since last run, automatically call `recorrelate.py` before pipeline
- [ ] Removes the last remaining manual operational step
- [ ] Store last-seen stack hash in a config file or DB table

### Correlator Improvements
- [ ] Track all sources a CVE was seen in via a JSONB array on `threat_records`
- [ ] Pass source array to triage prompt as additional exploitability signal
- [ ] Add index on `threat_records.cvss_score` to speed up `get_records_for_correlation()` query
- [ ] Add GIN index on `threat_records.raw_data` for JSON key lookups to speed up CPE queries

### Analysis Improvements
- [ ] Migrate triage results from `raw_data` JSONB keys to proper columns if triage becomes a first-class query target
- [ ] Source tracking: pass all sources a CVE was seen in to triage as an exploitability signal

### RAG and Chat Improvements
- [ ] Embedding-time content screening for instruction-like patterns in ingested descriptions
- [ ] Log retrieved chunks alongside each query for retrieval observability
- [ ] Output validation pass to detect anomalous LLM responses

### Security Hardening
- [ ] Audit all external data paths for prompt injection surface area
- [ ] Add rate limiting to FastAPI endpoints before any external exposure
- [ ] Add API key auth to FastAPI endpoints before any external exposure

### Testing
- [ ] Unit tests for feed normalization (one test per feed, covers happy path and missing fields)
- [ ] Unit tests for correlator alias matching and CPE parsing
- [ ] Unit tests for alias_generator validation logic
- [ ] Unit tests for chat pipeline intent classification and retrieval path routing
- [ ] Integration test for full ingestion to alert pipeline end to end
- [ ] Integration test for correlator against a known CVE and known asset
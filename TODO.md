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
- [x] `ui/app.py` - test Streamlit UI end to end
- [x] End to end test: ask a question about a known ingested CVE and verify grounded response

## Phase 6: Scheduler
- [ ] `scripts/scheduler.py` - wire in `run_ingestion` and `run_correlator` jobs
- [ ] Test scheduled runs at configured interval

## Phase 7: Polish
- [ ] Add unit tests for feed normalization
- [ ] Add unit tests for correlator matching logic
- [ ] Add integration test for full ingestion to alert pipeline
- [ ] Review and clean up all TODO comments in source files
- [ ] Update README with final usage instructions and demo GIF
- [ ] Final git review and push

## Future Improvements

### Dependency Scanner (high value portfolio addition)
- [ ] Build `scripts/scan_dependencies.py` that auto-populates `stack.yaml` libraries section
- [ ] Parse `requirements.txt` and `pip freeze` output for Python dependencies
- [ ] Parse `package.json` and `package-lock.json` for Node dependencies
- [ ] Parse `go.mod` for Go dependencies
- [ ] Parse `Gemfile.lock` for Ruby dependencies
- [ ] Run scan as a pre-step before correlator to keep stack.yaml current automatically
- [ ] Flag transitive dependencies separately from direct dependencies in stack.yaml

### Correlator Improvements
- [ ] Track all sources a CVE was seen in via a JSONB array on `threat_records`
- [ ] Pass source array to triage prompt as additional exploitability signal
- [ ] Add `exposure_results` persistence: write confirmed exposures to the database table
- [ ] Gate correlator on `exposure_results` table to avoid re-correlating already-confirmed exposures
- [ ] Add index on `threat_records.cvss_score` to speed up `get_records_for_correlation()` query
- [ ] Add index on `threat_records.raw_data` for JSON key lookups to speed up CPE queries

### Analysis Improvements
- [ ] Migrate triage results from `raw_data` JSONB keys to proper columns if triage becomes a first-class query target
- [ ] Source tracking: pass all sources a CVE was seen in to triage as an exploitability signal

### RAG and Chat Improvements
- [ ] XML delimiter wrapping on retrieved embedding chunks at query time in `chat/pipeline.py`
- [ ] Conversation history support in `ChatPipeline` for multi-turn analyst sessions
- [ ] Expose exposure and playbook data to the chat interface so analysts can query confirmed exposures

### API Layer (future)
- [ ] `api/routes/threats.py` - GET /threats with severity and date filters
- [ ] `api/routes/chat.py` - POST /chat endpoint wrapping ChatPipeline.query()
- [ ] `api/routes/alerts.py` - POST /correlate to trigger a manual correlation run, GET /exposures to return confirmed exposures
- [ ] Wire routes into `api/main.py`
- [ ] Add API key auth before any external exposure
- [ ] Add rate limiting to all endpoints

### Security Hardening
- [ ] Audit all external data paths for prompt injection surface area
- [ ] Add rate limiting to FastAPI endpoints
- [ ] Add API key auth to FastAPI endpoints before any external exposure

CHAT PIPELINE
- [ ] Increase TOP_K_RESULTS (currently 5) and evaluate whether broader retrieval improves answer relevance
- [ ] Hybrid retrieval mode: combine similarity search with SQL filters on severity and published_at
  for temporal queries ("most recent", "this week", etc.)
- [ ] Embedding-time content screening for instruction-like patterns in ingested descriptions
- [ ] Log retrieved chunks alongside each query for retrieval observability
- [ ] Output validation pass to detect anomalous LLM responses

## Correlator Improvements
- Add ASSET_ALIASES map to correlator.py for Stage 1 keyword matching.
  Current matching is too literal — misses "PostgreSQL" vs "postgresql",
  "GitHub Actions" vs "github-actions", "React.js" vs "react", etc.
  Implement alias lookup in _extract_candidates() before keyword fallback.
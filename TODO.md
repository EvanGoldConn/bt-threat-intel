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
- [ ] Copy `config/stack.example.yaml` to `config/stack.yaml` and fill in real environment
- [ ] `correlator/correlator.py` - implement `get_all_assets()` and `correlate()`
- [ ] End to end test: run `scripts/run_correlator.py` and confirm exposures are detected

## Phase 4: Alerting
- [ ] `alerting/alerter.py` - implement `_cli_alert()`
- [ ] `alerting/alerter.py` - implement `_slack_alert()`
- [ ] `alerting/alerter.py` - implement `alert_high_severity()`
- [ ] Set up Slack workspace and configure webhook URL in `.env`
- [ ] End to end test: trigger an alert and confirm CLI and Slack output

## Phase 5: Analyst Chat Interface
- [ ] `chat/pipeline.py` - implement `_format_context()`
- [ ] `chat/pipeline.py` - implement `query()`
- [ ] `ui/app.py` - test Streamlit UI end to end
- [ ] End to end test: ask a question about a known ingested CVE and verify grounded response

## Phase 6: API Layer
- [ ] `api/routes/threats.py` - endpoints for querying threat records
- [ ] `api/routes/chat.py` - endpoint for analyst chat queries
- [ ] `api/routes/alerts.py` - endpoint for triggering manual alerts
- [ ] Wire routes into `api/main.py`
- [ ] End to end test: hit all endpoints and confirm correct responses

## Phase 7: Scheduler
- [ ] `scripts/scheduler.py` - wire in `run_ingestion` and `run_correlator` jobs
- [ ] Test scheduled runs at configured interval

## Phase 8: Polish
- [ ] Add unit tests for feed normalization
- [ ] Add unit tests for correlator matching logic
- [ ] Add integration test for full ingestion to alert pipeline
- [ ] Review and clean up all TODO comments in source files
- [ ] Update README with final usage instructions and demo GIF
- [ ] Final git review and push
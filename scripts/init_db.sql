-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Stores normalized CVE and threat records from all ingestion sources
CREATE TABLE IF NOT EXISTS threat_records (
    id              SERIAL PRIMARY KEY,
    cve_id          TEXT UNIQUE,
    source          TEXT NOT NULL,
    title           TEXT,
    description     TEXT,
    cvss_score      FLOAT,
    cvss_vector     TEXT,
    severity        TEXT,
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,
    reference_urls      JSONB,
    raw_data        JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Stores vector embeddings for semantic search
CREATE TABLE IF NOT EXISTS threat_embeddings (
    id              SERIAL PRIMARY KEY,
    threat_id       INTEGER REFERENCES threat_records(id) ON DELETE CASCADE,
    embedding       vector(768),
    embedded_at     TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT threat_embeddings_threat_id_unique UNIQUE (threat_id)
);

-- Stores TTP mapping results from LLM analysis
CREATE TABLE IF NOT EXISTS ttp_mappings (
    id              SERIAL PRIMARY KEY,
    threat_id       INTEGER REFERENCES threat_records(id) ON DELETE CASCADE,
    tactic          TEXT,
    technique_id    TEXT,
    technique_name  TEXT,
    confidence      TEXT,
    mapped_at       TIMESTAMPTZ DEFAULT NOW()
);

-- Stores asset exposure results from the correlator
CREATE TABLE IF NOT EXISTS exposure_results (
    id              SERIAL PRIMARY KEY,
    threat_id       INTEGER REFERENCES threat_records(id) ON DELETE CASCADE,
    asset_name      TEXT,
    asset_version   TEXT,
    is_exposed      BOOLEAN,
    rationale       TEXT,
    assessed_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Stores generated IR playbooks
CREATE TABLE IF NOT EXISTS ir_playbooks (
    id              SERIAL PRIMARY KEY,
    threat_id       INTEGER REFERENCES threat_records(id) ON DELETE CASCADE,
    content         TEXT,
    generated_at    TIMESTAMPTZ DEFAULT NOW()
);

-- Index for fast vector similarity search
CREATE INDEX IF NOT EXISTS threat_embeddings_vector_idx
    ON threat_embeddings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

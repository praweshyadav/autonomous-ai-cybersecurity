CREATE TABLE IF NOT EXISTS incidents (
    incident_id UUID PRIMARY KEY,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,

    severity VARCHAR(20) NOT NULL,
    primary_family VARCHAR(100) NOT NULL,

    confidence DOUBLE PRECISION NOT NULL,

    event_count INTEGER NOT NULL,

    source_ips JSONB NOT NULL DEFAULT '[]'::jsonb,
    destination_ips JSONB NOT NULL DEFAULT '[]'::jsonb,
    destination_ports JSONB NOT NULL DEFAULT '[]'::jsonb,
    protocols JSONB NOT NULL DEFAULT '[]'::jsonb,

    family_distribution JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT incidents_confidence_range
        CHECK (confidence >= 0.0 AND confidence <= 1.0),

    CONSTRAINT incidents_event_count_positive
        CHECK (event_count > 0)
);


CREATE INDEX IF NOT EXISTS idx_incidents_start_time
    ON incidents (start_time);


CREATE INDEX IF NOT EXISTS idx_incidents_severity
    ON incidents (severity);


CREATE INDEX IF NOT EXISTS idx_incidents_primary_family
    ON incidents (primary_family);


CREATE INDEX IF NOT EXISTS idx_incidents_created_at
    ON incidents (created_at);
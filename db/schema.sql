-- ============================================================
-- Incidents
-- ============================================================

CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(50) PRIMARY KEY,

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


-- ============================================================
-- Security Events
-- ============================================================

CREATE TABLE IF NOT EXISTS security_events (
    event_id UUID PRIMARY KEY,

    timestamp TIMESTAMPTZ NOT NULL,

    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),

    src_port INTEGER,
    dst_port INTEGER,

    protocol INTEGER,
    protocol_name VARCHAR(50),

    binary_prediction INTEGER NOT NULL DEFAULT 0,

    attack_family VARCHAR(100) NOT NULL DEFAULT 'Benign',

    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    source_file TEXT,

    true_label TEXT,
    true_attack_family VARCHAR(100),

    event_type VARCHAR(100),

    windows_event_id INTEGER,

    username TEXT,
    domain TEXT,

    process_name TEXT,

    firewall_action VARCHAR(100),

    raw_log TEXT,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT security_events_confidence_range
        CHECK (confidence >= 0.0 AND confidence <= 1.0),

    CONSTRAINT security_events_binary_prediction_valid
        CHECK (binary_prediction IN (0, 1))
);


-- ============================================================
-- Incident ↔ Security Event Relationship
-- ============================================================

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id VARCHAR(50) NOT NULL,

    event_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (incident_id, event_id),

    CONSTRAINT fk_incident_events_incident
        FOREIGN KEY (incident_id)
        REFERENCES incidents (incident_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_incident_events_event
        FOREIGN KEY (event_id)
        REFERENCES security_events (event_id)
        ON DELETE CASCADE
);


-- ============================================================
-- Security Event Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
    ON security_events (timestamp);

CREATE INDEX IF NOT EXISTS idx_security_events_src_ip
    ON security_events (src_ip);

CREATE INDEX IF NOT EXISTS idx_security_events_dst_ip
    ON security_events (dst_ip);

CREATE INDEX IF NOT EXISTS idx_security_events_attack_family
    ON security_events (attack_family);

CREATE INDEX IF NOT EXISTS idx_security_events_event_type
    ON security_events (event_type);

CREATE INDEX IF NOT EXISTS idx_security_events_created_at
    ON security_events (created_at);


-- ============================================================
-- Incident ↔ Event Indexes
-- ============================================================

CREATE INDEX IF NOT EXISTS idx_incident_events_event_id
    ON incident_events (event_id);

CREATE INDEX IF NOT EXISTS idx_incident_events_incident_id
    ON incident_events (incident_id);

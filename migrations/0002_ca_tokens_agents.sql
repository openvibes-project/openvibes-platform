-- OpenVIBES platform schema version 2: the CA certificates the platform
-- issues under (public material only; keys stay files).
CREATE TABLE ca_certificates (
    fingerprint_sha256 bytea PRIMARY KEY CHECK (length(fingerprint_sha256) = 32),
    role text NOT NULL CHECK (role IN ('root', 'intermediate')),
    pem text NOT NULL,
    not_after timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON ca_certificates TO openvibes_ingest;

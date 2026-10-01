-- OpenVIBES platform schema version 31: open ports and running services per
-- host (protocol P15, Assets v2). Additive only: two tables replaced per
-- report, like host_packages, and two agent columns.

CREATE TABLE host_listeners (
    agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
    protocol text NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    address inet NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    exposed boolean NOT NULL,
    -- The owner, when the agent could see it (see agents.services_owners).
    service text,
    program text,
    PRIMARY KEY (agent_id, protocol, address, port)
);
-- The fleet Ports view groups by port.
CREATE INDEX host_listeners_port ON host_listeners (protocol, port);

CREATE TABLE host_services (
    agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
    unit text NOT NULL,
    programs text[] NOT NULL,
    processes integer NOT NULL CHECK (processes >= 0),
    -- A user name, or the uid as text when the name is not known.
    run_as text,
    PRIMARY KEY (agent_id, unit)
);
CREATE INDEX host_services_unit ON host_services (unit);

ALTER TABLE agents
    ADD COLUMN services_sha256 text CHECK (services_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN services_at timestamptz,
    -- complete: every owner the host has is named; partial: owners may be
    -- missing (no opt-in capability on the agent, or a capped walk).
    ADD COLUMN services_owners text CHECK (services_owners IN ('complete', 'partial'));

GRANT SELECT, INSERT, DELETE ON host_listeners, host_services TO "openvibes-ingest";
GRANT SELECT ON host_listeners, host_services TO "openvibes-console";

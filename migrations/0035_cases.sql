-- OpenVIBES platform schema version 35: cases (docs/specs/2026-10-04-console-cases-design.md).
-- A case is where one investigation happens: a title, a status, items
-- that link to existing objects (never copies), and an append-only
-- timeline. Cases are visible by the viewer's asset-group scope, which the
-- console enforces in SQL through each item's agent.
CREATE TABLE cases (
    case_id uuid PRIMARY KEY,
    -- Shown as C-<number>; assigned by the database, never reused.
    number bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
    status text NOT NULL CHECK (status IN ('open', 'investigating', 'closed')),
    resolution text NULL CHECK (resolution IN ('mitigated', 'false_positive', 'accepted_risk')),
    resolution_note text NULL CHECK (char_length(resolution_note) BETWEEN 1 AND 4000),
    accepted_until timestamptz NULL,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    assignee_user_id uuid NULL REFERENCES console_users,
    opened_by_user_id uuid NOT NULL REFERENCES console_users,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    closed_at timestamptz NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    -- A case is closed exactly when it has a resolution and a note, and
    -- accepted risk has an end date.
    CHECK ((status = 'closed') = (resolution IS NOT NULL)),
    CHECK ((status = 'closed') = (resolution_note IS NOT NULL)),
    CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
    CHECK ((resolution = 'accepted_risk') = (accepted_until IS NOT NULL))
);
CREATE INDEX cases_updated_idx ON cases (updated_at DESC, case_id DESC);
CREATE INDEX cases_assignee_idx ON cases (assignee_user_id) WHERE assignee_user_id IS NOT NULL;
CREATE INDEX cases_opened_by_idx ON cases (opened_by_user_id);
-- Accepted risk that has run out reopens its case.
CREATE INDEX cases_accepted_until_idx ON cases (accepted_until)
    WHERE status = 'closed' AND resolution = 'accepted_risk';

CREATE TABLE case_items (
    item_id uuid PRIMARY KEY,
    -- Order of adding, for items added in the same instant.
    seq bigint GENERATED ALWAYS AS IDENTITY,
    case_id uuid NOT NULL REFERENCES cases ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('alarm', 'finding', 'vulnerability', 'host', 'software')),
    -- The object's id as the console's panels write it: the alarm id;
    -- agent/rule_set/rule; agent/advisory; the agent id; manager/name.
    ref text NOT NULL CHECK (char_length(ref) BETWEEN 1 AND 512),
    -- The agent that decides who sees the item (null for software, which
    -- is visible to every reader). Not a foreign key: it only filters.
    agent_id text NULL,
    -- True while the case is not closed.
    active boolean NOT NULL DEFAULT true,
    outcome text NULL CHECK (outcome IN ('resolved', 'false_positive', 'accepted_risk')),
    outcome_note text NULL CHECK (char_length(outcome_note) BETWEEN 1 AND 4000),
    added_by_user_id uuid NOT NULL REFERENCES console_users,
    added_at timestamptz NOT NULL,
    UNIQUE (case_id, kind, ref),
    CHECK ((kind = 'software') = (agent_id IS NULL)),
    -- Marking something false positive or accepted risk needs a note.
    CHECK (outcome IS NULL OR outcome = 'resolved' OR outcome_note IS NOT NULL)
);
CREATE INDEX case_items_case_idx ON case_items (case_id);
CREATE INDEX case_items_agent_idx ON case_items (agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX case_items_lookup_idx ON case_items (kind, ref);
-- One alarm, finding, or vulnerability on a host is in at most one open
-- case. Hosts and software can be in many.
CREATE UNIQUE INDEX case_items_exclusive_idx ON case_items (kind, ref)
    WHERE active AND kind IN ('alarm', 'finding', 'vulnerability');

CREATE TABLE case_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id uuid NOT NULL REFERENCES cases ON DELETE CASCADE,
    at timestamptz NOT NULL,
    actor_user_id uuid NULL REFERENCES console_users,
    kind text NOT NULL CHECK (kind IN ('created', 'note', 'status', 'assigned', 'severity',
        'item_added', 'item_removed', 'item_outcome', 'resolved', 'reopened')),
    -- The note's text; plain text.
    body text NULL CHECK (char_length(body) BETWEEN 1 AND 4000),
    -- Structured facts about the change (never the note).
    detail jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object')
);
CREATE INDEX case_events_case_idx ON case_events (case_id, event_id);

-- The timeline is append-only, whoever connects.
CREATE FUNCTION case_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'case_events is append-only';
END $$;
CREATE TRIGGER case_events_append_only BEFORE UPDATE OR DELETE ON case_events
    FOR EACH ROW EXECUTE FUNCTION case_events_append_only();

INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('cases.manage', 'agent')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('analyst', 'cases.manage'),
       ('admin', 'cases.manage')
ON CONFLICT DO NOTHING;

GRANT SELECT, INSERT, UPDATE ON cases TO "openvibes-console";
GRANT SELECT, INSERT, UPDATE, DELETE ON case_items TO "openvibes-console";
GRANT SELECT, INSERT ON case_events TO "openvibes-console";

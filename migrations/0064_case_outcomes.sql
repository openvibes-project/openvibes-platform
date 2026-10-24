-- openvibes: needs-backup
-- OpenVIBES platform schema version 64: case item outcomes (roles plan
-- 2026-10-25 step 5d, user decision 1 and rulings 1 and 3). Items carry the
-- outcomes, so a case closes with a closing note (`resolution_note`) and no
-- resolution; old closed cases keep theirs, and `accepted_until` reopens
-- them as before. Two new outcomes, `confirmed_malicious` and `expected`,
-- need a note like every outcome but `resolved`. Risk accepted has its
-- re-open date per item now: `outcome_until`.
--
-- Backfill: an accepted-risk item of a case closed as accepted risk takes
-- that case's `accepted_until`. Any other accepted-risk item had no date, so
-- it takes `added_at` + 90 days (the plan's choice: a quarter, well inside
-- the 365 days the console allows), which brings an old acceptance back for
-- review rather than leaving it undated. Such an item whose 90 days have passed reopens
-- its closed case on the console's next lazy check.
--
-- The update only fills the new column and the relaxed check accepts every
-- existing row, but the backfilled dates decide reopens, so it is marked
-- needs-backup (an UPDATE, board #77): Update backs up first. The column
-- falls under the existing table grants to `openvibes-console`.
ALTER TABLE case_items DROP CONSTRAINT case_items_outcome_check;
ALTER TABLE case_items ADD CONSTRAINT case_items_outcome_check
    CHECK (outcome IN ('resolved', 'false_positive', 'accepted_risk',
                       'confirmed_malicious', 'expected'));
ALTER TABLE case_items ADD COLUMN outcome_until timestamptz NULL;
UPDATE case_items i
SET outcome_until = COALESCE(
    (SELECT c.accepted_until FROM cases c
     WHERE c.case_id = i.case_id AND c.status = 'closed' AND c.resolution = 'accepted_risk'),
    -- 90 days of 24 hours, so the server's time zone (DST) cannot shift it.
    i.added_at + interval '2160 hours')
WHERE i.outcome = 'accepted_risk';
-- IS NOT DISTINCT FROM: no date on an item without an outcome either.
ALTER TABLE case_items ADD CONSTRAINT case_items_outcome_until_check
    CHECK ((outcome IS NOT DISTINCT FROM 'accepted_risk') = (outcome_until IS NOT NULL));
-- The lazy reopen finds the acceptances that ran out.
CREATE INDEX case_items_outcome_until_idx ON case_items (outcome_until)
    WHERE outcome = 'accepted_risk';

-- `(status = 'closed') = (resolution IS NOT NULL)` from migration 35: a
-- resolution now only on a closed case, which no longer needs one.
ALTER TABLE cases DROP CONSTRAINT cases_check;
ALTER TABLE cases ADD CONSTRAINT cases_resolution_closed_check
    CHECK (resolution IS NULL OR status = 'closed');

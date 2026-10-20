-- OpenVIBES platform schema version 57: agent version order and a faster
-- host-group rule check for the Hosts list (roles plan 2026-10-20).
--
-- Version order (ruling 7), the same rules as platform-store's
-- version_order.rs and close to the web's `olderThan` (views/lists/rows.ts):
-- numeric segments compared (the shorter padded with zeros), a pre-release
-- is older than its release, build metadata ignored. Unlike the web, it
-- ignores the pre-release tag itself (1.0.0-rc1 and 1.0.0-rc2 are equal) and
-- gives NULL for an unknown or non-numeric version. Both
-- functions are single expressions so PostgreSQL inlines them; a function
-- call per host cost 750 ms at 20,000 hosts.

-- The numeric segments of `v` without pre-release, build or trailing zero
-- segments: '1.2.0-rc1+b' gives {1,2}, so plain array order is padded
-- order. NULL when empty or any segment is not 1–9 digits.
CREATE FUNCTION console_version_parts(v text) RETURNS int[] LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN split_part(split_part(v, '+', 1), '-', 1) ~ '^[0-9]{1,9}(\.[0-9]{1,9})*$'
         THEN string_to_array(regexp_replace(split_part(split_part(v, '+', 1), '-', 1), '(\.0+)+$', ''), '.')::int[]
         END $$;

-- Whether `v` is older than `latest`; NULL when either is unknown.
CREATE FUNCTION console_version_older(v text, latest text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN console_version_parts(v) IS NULL OR console_version_parts(latest) IS NULL THEN NULL
              WHEN console_version_parts(v) <> console_version_parts(latest)
              THEN console_version_parts(v) < console_version_parts(latest)
              ELSE strpos(split_part(v, '+', 1), '-') > 0 AND strpos(split_part(latest, '+', 1), '-') = 0 END $$;

-- One rule condition with its values prepared once per condition (`likes`:
-- the hostname globs as LIKE patterns, default escape '\'; `nets`: the ip
-- values as inet). No subquery, so it inlines: the Hosts list evaluates it
-- per (host, condition) in one pass, 66 ms at 20,000 hosts and 10 rules
-- against 4.7 s through console_host_in_group.
CREATE FUNCTION console_condition_holds_prepared(a agents, field text, negate boolean, vals text[],
                                                 likes text[], nets inet[]) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN field = 'os_family'    THEN a.os_family IS NOT NULL     AND negate <> (a.os_family = ANY (vals))
    WHEN field = 'distribution' THEN a.distribution IS NOT NULL  AND negate <> (a.distribution = ANY (vals))
    WHEN field = 'hostname'     THEN a.hostname IS NOT NULL      AND negate <> (lower(a.hostname) LIKE ANY (likes))
    WHEN field = 'ip'           THEN a.last_address IS NOT NULL  AND negate <> (a.last_address <<= ANY (nets))
    ELSE false END $$;

-- The prepared values of one condition.
CREATE FUNCTION console_condition_likes(vals text[]) RETURNS text[] LANGUAGE sql IMMUTABLE AS $$
  SELECT ARRAY(SELECT console_glob_like(v) FROM unnest(vals) v) $$;

-- Same answers as before (migration 53), now through the prepared form so
-- the rule lives in one place.
CREATE OR REPLACE FUNCTION console_condition_holds(a agents, field text, negate boolean, vals text[]) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT console_condition_holds_prepared(a, field, negate, vals, console_condition_likes(vals),
                                          CASE WHEN field = 'ip' THEN vals::inet[] END) $$;

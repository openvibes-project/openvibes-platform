-- OpenVIBES platform schema version 13: other distributions via OSV.dev
-- (spec 2026-09-25-osv-distributions-design.md).
--
-- A fixed package keeps its whole version string and says how to compare
-- it (rpm or dpkg) and what it names (a binary, or a Debian source
-- package). A range may start later than the first version (introduced)
-- or end without a known fix (fixed NULL, optionally last_affected).
ALTER TABLE advisory_packages
    ADD COLUMN scheme text NOT NULL DEFAULT 'rpm' CHECK (scheme IN ('rpm', 'dpkg')),
    ADD COLUMN match_on text NOT NULL DEFAULT 'binary' CHECK (match_on IN ('binary', 'source')),
    ADD COLUMN introduced text,
    ADD COLUMN fixed text,
    ADD COLUMN last_affected text;
UPDATE advisory_packages SET fixed = epoch || ':' || version || '-' || release;
ALTER TABLE advisory_packages
    DROP CONSTRAINT advisory_packages_pkey,
    DROP COLUMN epoch,
    DROP COLUMN version,
    DROP COLUMN release;
CREATE UNIQUE INDEX advisory_packages_key
    ON advisory_packages (advisory_id, name, arch, match_on, COALESCE(introduced, ''));
-- The release advisories are published for: RHEL rebuilds by major
-- version (os-release says 9.4, their advisories say 9).
ALTER TABLE agents ADD COLUMN os_release text GENERATED ALWAYS AS (
    CASE WHEN os_id IN ('rocky', 'almalinux') THEN split_part(os_version, '.', 1)
         ELSE os_version END) STORED;

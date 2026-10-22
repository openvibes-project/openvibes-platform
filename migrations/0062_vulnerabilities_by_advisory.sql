-- OpenVIBES platform schema version 62: every pair of one advisory, fixed
-- or not (roles plan 2026-10-22 step 5b, Vulnerabilities list). The list
-- reads the package names and fixed versions of the pairs of advisories
-- with several package entries (a Fedora bundle, OSV ranges), and the
-- open-only `vulnerabilities_open` index misses fixed pairs. Additive.
CREATE INDEX vulnerabilities_advisory ON vulnerabilities (advisory_id);

-- OpenVIBES platform schema version 16: console verification of signed
-- bundles needs read-only access to their public trust keys.
GRANT SELECT ON rule_trust_keys TO openvibes_console;

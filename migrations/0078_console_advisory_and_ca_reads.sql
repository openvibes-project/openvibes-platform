-- The console reads two tables it was never granted (#572): advisory_packages
-- (the Vulnerabilities list and a vulnerability's page, since the list by
-- CVE) and ca_certificates (the About page's certificate dates). Both hold
-- public data: package names and fixed versions, and CA certificates.
GRANT SELECT ON advisory_packages, ca_certificates TO "openvibes-console";

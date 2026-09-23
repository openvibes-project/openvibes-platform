# platform-pki

Certificate issuing for the built-in CA mode (architecture spec, section 5).
No I/O and no network: functions take and return PEM strings; the admin CLI
and ingest do the file and database work.

## CA hierarchy

| Certificate | Lifetime | Constraints | Made by |
|---|---|---|---|
| Root (`OpenVIBES Root CA`) | 10 years (3652 days) | CA, path length 1, keyCertSign + cRLSign | `generate_root(now)`, offline |
| Intermediate (`OpenVIBES Intermediate CA`) | 2 years (730 days) | CA, path length 0 | key + CSR from `intermediate_request()` on the ingest host; signed offline by `sign_intermediate(&root, csr, now)` |
| Server | 90 days | server auth, SANs from the given names | `Issuer::issue_server(names, now)`; `cert_pem` is leaf + intermediate |

All keys are ECDSA P-256; serials are 16 random bytes with the top bit
cleared. `KeyAndCert`'s `Debug` output redacts the key.

## Interface

- `Issuer::load(cert_pem, key_pem)`: refuses a non-CA certificate (`NotCa`)
  and a key that does not belong to it (`KeyMismatch`).
- `verify_signed_by(cert, issuer_cert)`: signature check (`NotSignedBy`).
- `sha256_fingerprint(cert)`: SHA-256 of the DER encoding.
- `PkiError`: `InvalidPem`, `InvalidCsr`, `UnsupportedKey`,
  `NonEmptySubject`, `KeyMismatch`, `NotCa`, `NotSignedBy`, `Generation`.
  Messages never contain key or certificate material.

## Test

`cargo test --locked -p platform-pki`

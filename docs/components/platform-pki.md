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

All keys are ECDSA P-256. Serials are 16 bytes whose first two bits are
`01` (126 random bits), so the DER encoding is always exactly those 16
bytes and matches what the database stores. `KeyAndCert`'s `Debug` output redacts the key.

## Agent CSRs and client certificates (used by ingest)

- `check_csr(pem) -> CheckedCsr`: at most 1 MiB; parsed and verified with
  x509-parser (`InvalidCsr`); the key must be ECDSA P-256 (`UnsupportedKey`);
  the subject must be empty (`NonEmptySubject`), because the platform assigns
  identity. Requested extensions are ignored. The certified key is taken from
  the CSR's key info, never inferred from its signature algorithm. `CheckedCsr::spki_sha256` is SHA-256 of
  the key's SubjectPublicKeyInfo DER.
- `Issuer::issue_client(&csr, agent_id, now, days) -> IssuedClient`: empty
  subject, SAN URI `openvibes:agent:<agent_id>`, EKU client auth only, not a
  CA, fresh 16-byte serial, valid `days` from `now` (whole seconds). `days`
  must be 1 to 365 (`InvalidValidity`); validity is clamped to the issuer's
  own expiry, and an expired issuer is refused (`IssuerExpired`). Issuing
  fails closed if the certificate's key hash differs from the CSR's.
  `chain_pem` is leaf then intermediate.
- `spki_sha256_of_cert(pem)`: the same hash for a presented certificate, so
  ingest can match it against `certificates.spki_sha256`.

## Tokens and agent ids

- `enrollment_token_sha256(token) -> Option<[u8; 32]>`: the one way tokens
  are hashed, used by both `openvibes-admin token create` and ingest.
  Accepts exactly 43 base64url characters (no padding, no whitespace) that
  decode to 32 bytes, and hashes the bytes.
- `is_agent_id(id)`: `agent.` + a lowercase hyphenated UUID, matching the
  database CHECK. `issue_client` refuses anything else (`InvalidAgentId`).

## Interface

- `Issuer::load(cert_pem, key_pem)`: refuses a non-CA certificate (`NotCa`)
  and a key that does not belong to it (`KeyMismatch`).
- `verify_signed_by(cert, issuer_cert)`: signature check (`NotSignedBy`).
- `check_intermediate(cert, root_cert, now)`: a CA with path length 0 that
  is not self-signed (`NotIntermediate`), signed by the root (`NotSignedBy`),
  and valid at `now` (`IssuerExpired`).
- `sha256_fingerprint(cert)`: SHA-256 of the DER encoding.
- `PkiError`: `InvalidPem`, `InvalidCsr`, `UnsupportedKey`,
  `NonEmptySubject`, `KeyMismatch`, `NotCa`, `NotSignedBy`, `Generation`,
  `InvalidValidity`, `IssuerExpired`, `InvalidAgentId`.
  Messages never contain key or certificate material.

## Test

`cargo test --locked -p platform-pki`

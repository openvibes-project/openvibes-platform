# platform-pki

Certificate issuing for the built-in CA mode (architecture spec, section 5).
No I/O and no network: functions take and return PEM strings; the admin CLI
and ingest do the file and database work.

## CA hierarchy

| Certificate | Lifetime | Constraints | Made by |
|---|---|---|---|
| Root (`OpenVIBES Root CA`) | 10 years (3652 days) | CA, path length 1, keyCertSign + cRLSign | `generate_root(now)`, offline |
| Intermediate (`OpenVIBES Intermediate CA`) | 2 years (730 days) | CA, path length 0 | key + CSR from `intermediate_request()` on the ingest host; signed offline by `sign_intermediate(&root, csr, now)` (capped at the root's expiry), which refuses a root key that is not the root certificate's (`KeyMismatch`) |
| Server | 90 days | server auth, SANs from the given names | `Issuer::issue_server(names, now)`; `cert_pem` is leaf + intermediate, then the CAs from `with_chain` |

An intermediate imported from a company PKI takes the place of the one
above; its root and any CAs between come from the company. Those middle CAs
are stored apart (`/etc/openvibes/pki/chain.crt`), never as trust anchors: they ride along in
server certificates (`Issuer::with_chain`) so clients can reach the root,
while agent client certificates still chain to our intermediate only.

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

## Company keys and `.p12` files

For importing an intermediate from a company PKI. Every key comes out as
plain PKCS#8 PEM (`Zeroizing`), and has loaded in rcgen once.

- Accepted keys: EC P-256, EC P-384, RSA 2048 to 4096 bits, Ed25519. RSA
  below 2048 bits is `WeakKey(bits)`; P-521, DSA and RSA above 4096 bits
  (ring's limit for signing) are `UnsupportedKey`.
- `pkcs8_pem(key_pem, password)`: the first PEM block (an `EC PARAMETERS`
  block is skipped), labelled `PRIVATE KEY`, `RSA PRIVATE KEY` (PKCS#1),
  `EC PRIVATE KEY` (SEC1, must name its curve) or `ENCRYPTED PRIVATE KEY`
  (PBES2 with an SHA-1 or SHA-2 PRF, AES-CBC or DES-EDE3-CBC). The PKCS#1
  and SEC1 forms may carry OpenSSL's traditional encryption
  (`Proc-Type: 4,ENCRYPTED`, `DEK-Info:` AES-128/192/256-CBC or
  DES-EDE3-CBC; key from EVP_BytesToKey with MD5). No password for a locked
  key is `KeyLocked`; one that does not open it is `WrongPassword`. Older
  encryptions (PBES1, other `DEK-Info` ciphers) are `OldEncryption`.
- `is_locked(key_pem)`: the first block is `ENCRYPTED PRIVATE KEY` or has a
  `DEK-Info` header.
- `key_info(pkcs8_pem) -> KeyInfo`: kind and bits; `Display` gives
  "an RSA key (3072 bits)", "an EC P-256 key", "an EC P-384 key",
  "an Ed25519 key".
- `is_p12(bytes)`: DER (starts with a SEQUENCE), not PEM text.
- `read_p12(bytes, password) -> P12`: `.p12`/`.pfx` with PBES2 (AES) or
  legacy 3DES/RC2 (p12-keystore). The first private key as PKCS#8, and every
  certificate in the file as PEM, the key's own one first. A failed MAC is
  `WrongPassword`. `P12`'s `Debug` redacts the key. p12-keystore keeps its
  own copy of the decrypted key, not wiped, until its archive drops at the
  end of `read_p12`; our copies are wiped (`Zeroizing`).

Fixtures are in `tests/fixtures`, made by `make.sh` (openssl 3.4 or newer);
its `README` lists them.

## Interface

- `certificates(pem) -> Vec<Vec<u8>>`: the DER of every `CERTIFICATE`
  block, in order (text outside blocks ignored, CRLF accepted); none for
  blank text. Setup compares server certificates with `chain.crt` this way.
- `common_name(pem) -> String`: the first certificate's common name ("an
  unnamed CA" without one). The Import screen names ours with it while the
  chain above is not whole.
- `check_chain(certs_pem, now) -> Chain`: the first certificate is ours
  and must not be self-signed (`IsRoot(cn)`); the path is built from the
  rest, in any order, CRLF or not, up to a self-signed root. Each link
  needs both the signature and the issuer name (DER, byte for byte, as
  agents chain by name). Certificates not on the path are ignored. Every
  certificate on the path must be a CA with keyCertSign when key usage is
  present (`NotCa(cn)`); a missing issuer, the root included, is
  `Missing(issuer cn)`. A CA with path length N may have at most N CAs
  below it, ours included (`NoCaBelow(cn)`); ours may carry any path
  length. Every certificate on the path must have started by `now`
  (`NotYetValid(latest not_before)`) and stay valid 90 days more
  (`Expiring(earliest not_after)`). `Chain` holds ours, `middle`
  (nearest first), `root`, our common name, the names above ours (root
  last) and the earliest `not_after`. Names without a common name read
  "an unnamed CA".
- `check_key(&chain, pkcs8_pem, now) -> KeyInfo`: `key_info`, then
  `Issuer::load` (`Pki(KeyMismatch)`), then a throwaway server certificate
  whose issuer bytes must equal our subject bytes (`Pki(NameMismatch)`):
  rcgen rebuilds the issuer name, and keeps one attribute per type, so a
  name with two `DC`s, say, would not chain.
- `Issuer::with_chain(middle_pem)`: the CAs to append to server
  certificates (each must parse, `InvalidPem`); blank text means none.
- `first_certificate(pem)`: the first `CERTIFICATE` block of a bundle as PEM
  (`InvalidPem` if none).
- `Issuer::load(cert_pem, key_pem)`: issues from the first certificate of a
  bundle (the new intermediate may precede the old one), so a server
  certificate's `cert_pem` is the leaf, that certificate, then only the
  CAs given to `with_chain`. Refuses a non-CA certificate (`NotCa`)
  and a key that does not belong to it (`KeyMismatch`).
- `verify_signed_by(cert, issuer_cert)`: signature check (`NotSignedBy`).
- `check_intermediate(cert, root_cert, now)`: a CA with path length 0 that
  is not self-signed (`NotIntermediate`), signed by the root (`NotSignedBy`),
  and valid at `now` (`IssuerExpired`).
- `check_signed_request(csr, cert, now)`: the answer to an intermediate
  request made before install: exactly one PEM block (`Several(n)`), the
  request's own key (`NotForRequest`; checked first, so another CA pasted
  by mistake, such as the root, reads as for a different request), a CA
  with path length 0 (`NotCa`), valid at `now` (`IssuerExpired`); returns
  `Signed` (subject and issuer common names, `not_after` as `YYYY-MM-DD`).
- `check_root_signed(root_cert, cert, now)`: one PEM block, a self-signed CA
  (`NotRoot`), valid at `now`, that signed `cert` (`NotSignedBy`) and may
  sign a CA: path length 0 is refused (`RootPathLen0`); returns the root's
  common name.
- `sha256_fingerprint(cert)`: SHA-256 of the DER encoding.
- `is_ca(cert)`: whether the first certificate is a CA (basicConstraints
  CA:TRUE).
- `not_before(cert)`, `not_after(cert)`: when the first certificate's
  validity starts and ends.
- `PkiError`: `InvalidPem`, `InvalidCsr`, `UnsupportedKey`,
  `NonEmptySubject`, `KeyMismatch`, `NotCa`, `NotSignedBy`, `Generation`,
  `InvalidValidity`, `IssuerExpired`, `InvalidAgentId`, `NotIntermediate`,
  `NotForRequest`, `Several(n)`, `NotRoot`, `RootPathLen0`, `KeyLocked`,
  `WrongPassword`, `WeakKey(bits)`, `OldEncryption`, `NameMismatch`.
  Messages never contain key or certificate material.

## Test

`cargo test --locked -p platform-pki`

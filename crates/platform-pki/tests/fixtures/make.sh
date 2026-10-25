#!/usr/bin/env bash
# Remakes the key and certificate fixtures for tests/keys.rs and the import
# tests. Needs openssl 3.4 or newer (x509 -not_before/-not_after). The outputs
# are committed; the tests never run openssl.
set -euo pipefail
cd "$(dirname "$0")"

PASS='correct horse'
FROM=20260101000000Z
UNTIL=20460101000000Z
SERIAL=1000
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

rsa() { openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "$1"; }
ec() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$2" -out "$1"; }

# ca_ext <pathlen, or "" for none>: extensions for a CA certificate.
ca_ext() {
  {
    echo "basicConstraints = critical, CA:TRUE${1:+, pathlen:$1}"
    echo "keyUsage = critical, keyCertSign, cRLSign"
    echo "subjectKeyIdentifier = hash"
  } > "$TMP/ext"
}

# sign <out.crt> <key> <CN> <issuer.crt> <issuer.key> [from] [until]
sign() {
  SERIAL=$((SERIAL + 1))
  openssl req -new -key "$2" -subj "/O=Lime Lab/CN=$3" -out "$TMP/csr"
  openssl x509 -req -in "$TMP/csr" -CA "$4" -CAkey "$5" -set_serial "$SERIAL" \
    -not_before "${6:-$FROM}" -not_after "${7:-$UNTIL}" -sha256 \
    -extfile "$TMP/ext" -out "$1"
}

# self_sign <out.crt> <key> <CN>
self_sign() {
  SERIAL=$((SERIAL + 1))
  openssl req -new -key "$2" -subj "/O=Lime Lab/CN=$3" -out "$TMP/csr"
  openssl x509 -req -in "$TMP/csr" -key "$2" -set_serial "$SERIAL" \
    -not_before "$FROM" -not_after "$UNTIL" -sha256 -extfile "$TMP/ext" -out "$1"
}

rsa root.key 4096
ca_ext 2
self_sign root.crt root.key "Lime Lab Root CA"

ec issuing.key P-384
ca_ext 1
sign issuing.crt issuing.key "Lime Lab Issuing CA" root.crt root.key

ca_ext ""
rsa ours-rsa.key 3072
sign ours-rsa.crt ours-rsa.key "Lime Lab OpenVIBES CA" issuing.crt issuing.key
openssl pkey -in ours-rsa.key -traditional -out ours-rsa.pkcs1.pem

ec ours-ec.pkcs8.pem P-256
sign ours-ec.crt ours-ec.pkcs8.pem "Lime Lab OpenVIBES CA" issuing.crt issuing.key
openssl pkey -in ours-ec.pkcs8.pem -traditional -out ours-ec.sec1.pem
openssl pkcs8 -topk8 -in ours-ec.pkcs8.pem -v2 aes-256-cbc -passout "pass:$PASS" \
  -out ours-ec.enc.pem
# A file holding the certificate, then its locked key.
cat ours-ec.crt ours-ec.enc.pem > ours-ec.combined.pem

# Older encryptions of the same keys: traditional PEM (Proc-Type/DEK-Info),
# PBES2 with SHA-1 or 3DES, and PBES1 (refused as too old).
openssl pkey -in ours-ec.pkcs8.pem -traditional -aes256 -passout "pass:$PASS" \
  -out ours-ec.trad-aes.pem
openssl pkey -in ours-rsa.key -traditional -des3 -passout "pass:$PASS" \
  -out ours-rsa.trad-3des.pem
openssl pkcs8 -topk8 -in ours-ec.pkcs8.pem -v2 aes-256-cbc -v2prf hmacWithSHA1 \
  -passout "pass:$PASS" -out ours-ec.enc-sha1.pem
openssl pkcs8 -topk8 -in ours-ec.pkcs8.pem -v2 des3 -passout "pass:$PASS" \
  -out ours-ec.enc-3des.pem
openssl pkcs8 -topk8 -in ours-ec.pkcs8.pem -v1 PBE-MD5-DES -provider legacy \
  -provider default -passout "pass:$PASS" -out ours-ec.pbes1.pem

ec short.key P-256
sign short.crt short.key "Lime Lab Short CA" issuing.crt issuing.key "$FROM" 20261201000000Z

ca_ext 0
ec strict.key P-256
sign strict.crt strict.key "Lime Lab Strict CA" root.crt root.key
ca_ext ""
ec under-strict.key P-256
sign under-strict.crt under-strict.key "Lime Lab Under Strict CA" strict.crt strict.key

# Two DC attributes: rcgen keeps one per type, so it cannot reproduce this
# name as the issuer of what it signs.
ec twin-dc.key P-256
SERIAL=$((SERIAL + 1))
openssl req -new -key twin-dc.key -subj "/DC=lab/DC=lime/O=Lime Lab/CN=Lime Lab Twin DC CA" \
  -out "$TMP/csr"
openssl x509 -req -in "$TMP/csr" -CA issuing.crt -CAkey issuing.key -set_serial "$SERIAL" \
  -not_before "$FROM" -not_after "$UNTIL" -sha256 -extfile "$TMP/ext" -out twin-dc.crt

# Extended key usage clientAuth only: agents refuse the server
# certificates it signs.
ca_ext ""
echo "extendedKeyUsage = clientAuth" >> "$TMP/ext"
ec client-only.key P-256
sign client-only.crt client-only.key "Lime Lab Client Only CA" root.crt root.key

rsa weak.key 1024
ec p521.key P-521
rsa big.key 6144

# A leaf for "not a CA", and an unrelated self-signed one for legacy.pfx.
{
  echo "basicConstraints = critical, CA:FALSE"
  echo "keyUsage = critical, digitalSignature"
  echo "extendedKeyUsage = serverAuth"
  echo "subjectAltName = DNS:web.lime.lab"
} > "$TMP/ext"
ec "$TMP/leaf.key" P-256
sign leaf-not-ca.crt "$TMP/leaf.key" "Lime Lab Web" issuing.crt issuing.key
ec "$TMP/web.key" P-256
self_sign "$TMP/web.crt" "$TMP/web.key" "Lime Lab Web"

cat issuing.crt root.crt > "$TMP/chain.pem"
openssl pkcs12 -export -inkey ours-ec.pkcs8.pem -in ours-ec.crt -certfile "$TMP/chain.pem" \
  -keypbe AES-256-CBC -certpbe AES-256-CBC -passout "pass:$PASS" -out modern.pfx
cat "$TMP/chain.pem" "$TMP/web.crt" > "$TMP/legacy-extra.pem"
openssl pkcs12 -export -legacy -inkey ours-ec.pkcs8.pem -in ours-ec.crt \
  -name "Lime Lab OpenVIBES CA" -certfile "$TMP/legacy-extra.pem" -passout "pass:$PASS" -out legacy.pfx

cat > README <<README
Test fixtures for platform-pki, made by make.sh with $(openssl version).
Every certificate is valid 2026-01-01 to 2046-01-01, except short.crt.
Password of every encrypted key, modern.pfx and legacy.pfx: correct horse

root.crt/.key            Lime Lab Root CA, RSA 4096, self-signed, path length 2
issuing.crt/.key         Lime Lab Issuing CA, EC P-384, under the root, path length 1
ours-rsa.crt/.key        Lime Lab OpenVIBES CA, RSA 3072, under issuing, no path length
ours-rsa.pkcs1.pem       the same key as RSA PRIVATE KEY (PKCS#1)
ours-ec.crt              Lime Lab OpenVIBES CA, EC P-256, under issuing, no path length
ours-ec.pkcs8.pem        its key as PRIVATE KEY (PKCS#8)
ours-ec.sec1.pem         the same key as EC PRIVATE KEY (SEC1)
ours-ec.enc.pem          the same key as ENCRYPTED PRIVATE KEY (PBES2, AES-256-CBC)
ours-ec.combined.pem     ours-ec.crt, then ours-ec.enc.pem, in one file
ours-ec.enc-sha1.pem     the same, PBES2 with the hmacWithSHA1 PRF
ours-ec.enc-3des.pem     the same, PBES2 with DES-EDE3-CBC
ours-ec.pbes1.pem        the same, PBES1 pbeWithMD5AndDES-CBC (too old)
ours-ec.trad-aes.pem     the same key as traditional encrypted EC PRIVATE KEY (AES-256-CBC)
ours-rsa.trad-3des.pem   ours-rsa.key as traditional encrypted RSA PRIVATE KEY (DES-EDE3-CBC)
short.crt/.key           Lime Lab Short CA, under issuing, valid until 2026-12-01
strict.crt/.key          Lime Lab Strict CA, under the root, path length 0
under-strict.crt/.key    Lime Lab Under Strict CA, a CA signed by strict
twin-dc.crt/.key         Lime Lab Twin DC CA, under issuing, subject with two DC attributes
client-only.crt/.key     Lime Lab Client Only CA, under the root, extended key usage clientAuth only
leaf-not-ca.crt          Lime Lab Web, CA:FALSE, under issuing
weak.key                 RSA 1024
p521.key                 EC P-521
big.key                  RSA 6144 (over ring's 4096-bit limit)
modern.pfx               ours-ec key, ours-ec.crt, issuing, root (AES-256-CBC)
legacy.pfx               as modern.pfx plus a self-signed Lime Lab Web (-legacy: 3DES/RC2), friendly name Lime Lab OpenVIBES CA
README

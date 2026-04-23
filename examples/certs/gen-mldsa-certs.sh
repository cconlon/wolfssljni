#!/usr/bin/env bash
#
# gen-mldsa-certs.sh
#
# Generates ML-DSA (FIPS 204) test certificate chains for the three parameter
# sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87 (CNSA 2.0). For each level produces
# a self-signed root CA plus a server entity cert and a client entity cert,
# both signed by the matching root.
#
# Output is written to ./pqc/ relative to wolfssljni's examples/certs/
# directory. Each level produces:
#
#   pqc/root-mldsaN.pem,  pqc/root-mldsaN-priv.pem,  pqc/root-mldsaN.der
#   pqc/server-mldsaN.pem, pqc/server-mldsaN-priv.pem, pqc/server-mldsaN.der
#   pqc/client-mldsaN.pem, pqc/client-mldsaN-priv.pem, pqc/client-mldsaN.der
#
# Run from this directory (examples/certs/):
#   ./gen-mldsa-certs.sh
#
# Requires OpenSSL 3.5 or newer (native ML-DSA support added in 3.5).
# Verified with OpenSSL 3.6.1.
#
# These certs are NOT pulled from upstream wolfSSL because the wolfSSL
# certs/mldsa/ directory ships only raw private keys (mldsa44_priv-only.der
# and friends), not PKCS#8-wrapped keys or X.509 chains. Once wolfSSL upstream
# upstream adds ML-DSA chain generation, this script can be retired in favor
# of update-certs.sh pulls.

set -euo pipefail

OUTDIR="./pqc"
mkdir -p "$OUTDIR"

# Verify OpenSSL knows about ML-DSA-44 before doing anything.
if ! openssl genpkey -algorithm ML-DSA-44 -out /dev/null 2>/dev/null; then
    echo "ERROR: This OpenSSL build lacks native ML-DSA support."
    echo "  openssl version: $(openssl version)"
    echo "  Need OpenSSL 3.5 or newer."
    exit 1
fi

# gen_chain <level> <subj_cn_prefix>
gen_chain() {
    local level="$1"
    local prefix="$2"
    local alg="ML-DSA-${level}"
    local out="$OUTDIR"
    local subj_base="/O=wolfSSL/C=US"

    echo "=== Generating ${alg} cert chain (root + server + client) ==="

    # Root CA: self-signed, valid 10 years, BasicConstraints CA:true
    openssl req -x509 -newkey "$alg" \
        -keyout "$out/root-mldsa${level}-priv.pem" \
        -out    "$out/root-mldsa${level}.pem" \
        -days 3650 -nodes \
        -subj "/CN=${prefix} Root CA${subj_base}" \
        -addext "basicConstraints=critical,CA:true" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        2>/dev/null
    openssl x509 -in "$out/root-mldsa${level}.pem" -outform DER \
        -out "$out/root-mldsa${level}.der"

    # Server entity cert
    openssl req -newkey "$alg" \
        -keyout "$out/server-mldsa${level}-priv.pem" \
        -out    "$out/server-mldsa${level}.csr" \
        -nodes \
        -subj "/CN=${prefix} server${subj_base}" \
        2>/dev/null
    openssl x509 -req -in "$out/server-mldsa${level}.csr" \
        -CA "$out/root-mldsa${level}.pem" \
        -CAkey "$out/root-mldsa${level}-priv.pem" \
        -CAcreateserial \
        -out "$out/server-mldsa${level}.pem" \
        -days 3650 \
        -extfile <(printf "%s\n%s\n%s\n" \
            "subjectAltName=DNS:example.com,IP:127.0.0.1" \
            "extendedKeyUsage=serverAuth" \
            "keyUsage=critical,digitalSignature") \
        2>/dev/null
    openssl x509 -in "$out/server-mldsa${level}.pem" -outform DER \
        -out "$out/server-mldsa${level}.der"
    rm "$out/server-mldsa${level}.csr"

    # Client entity cert (for mutual auth tests)
    openssl req -newkey "$alg" \
        -keyout "$out/client-mldsa${level}-priv.pem" \
        -out    "$out/client-mldsa${level}.csr" \
        -nodes \
        -subj "/CN=${prefix} client${subj_base}" \
        2>/dev/null
    openssl x509 -req -in "$out/client-mldsa${level}.csr" \
        -CA "$out/root-mldsa${level}.pem" \
        -CAkey "$out/root-mldsa${level}-priv.pem" \
        -CAcreateserial \
        -out "$out/client-mldsa${level}.pem" \
        -days 3650 \
        -extfile <(printf "%s\n%s\n" \
            "extendedKeyUsage=clientAuth" \
            "keyUsage=critical,digitalSignature") \
        2>/dev/null
    openssl x509 -in "$out/client-mldsa${level}.pem" -outform DER \
        -out "$out/client-mldsa${level}.der"
    rm "$out/client-mldsa${level}.csr"

    # Cleanup OpenSSL serial-number file
    rm -f "$out/root-mldsa${level}.srl"
}

# ML-DSA-44 / Cat 2 -- baseline PQC signatures
gen_chain 44 "ML-DSA-44"

# ML-DSA-65 / Cat 3 -- balanced signature variant
gen_chain 65 "ML-DSA-65"

# ML-DSA-87 / Cat 5 -- CNSA 2.0 mandated parameter set
gen_chain 87 "ML-DSA-87"

echo ""
echo "=== Done. Files in $OUTDIR/ : ==="
ls -1 "$OUTDIR"/ | grep -E "mldsa(44|65|87)" | sort

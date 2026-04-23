#!/usr/bin/env bash
#
# update-jks-pqc.sh
#
# Generates ML-DSA (FIPS 204) JKS keystores for wolfJSSE PQC tests.
#
# Why this script exists:
#   - JDK 24+ added ML-DSA via JEP 497 (KeyFactory, KeyPairGenerator,
#     Signature, KeyTool support). Prior JDK versions cannot read ML-DSA
#     private keys via standard JCE.
#   - OpenSSL 3.5+ and JDK 24+ disagree on the ML-DSA private key encoding
#     (seed-only vs expanded form). Cross-toolchain JKS conversion is
#     unreliable.
#   - Therefore, the simplest portable path is to use JDK 24+ keytool
#     to generate self-signed ML-DSA certs directly into JKS, no
#     openssl involvement on the keystore side.
#
# Requirements:
#   - JDK 24 or newer in PATH, OR JAVA_HOME pointing at a JDK 24+ install.
#
# Output: examples/provider/server-mldsa{44,65,87}.jks containing a
# self-signed ML-DSA cert + matching private key, alias "server-mldsaN",
# password "wolfSSL test".
#
# Tests that consume these JKS files (WolfSSLPQCAuthJksTest) skip cleanly on
# JDK < 24 via a runtime KeyFactory.getInstance("ML-DSA") probe, so checking
# the JKS files in is safe when CI runs on Java 8.

set -euo pipefail

PASSWD="wolfSSL test"
OUT_DIR="$(dirname "$0")"

KT="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"

# Verify JDK 24+
if ! "$KT" -genkeypair -keyalg ML-DSA -alias _probe \
        -keystore /tmp/_pqc_probe_$$.jks -storepass "$PASSWD" \
        -dname "CN=probe" >/dev/null 2>&1; then
    echo "ERROR: keytool does not support ML-DSA. Need JDK 24+." >&2
    echo "  Tried: $KT" >&2
    "$KT" -version 2>&1 || true
    rm -f /tmp/_pqc_probe_$$.jks
    exit 1
fi
rm -f /tmp/_pqc_probe_$$.jks

# Generate proper cert chain per ML-DSA level: a CA keypair signs a server
# cert. Output is two files per level:
#   server-mldsaN.jks   -- private key + server cert chain (server+root)
#   ca-mldsaN.jks       -- root cert only (truststore)
gen_jks() {
    local level="$1"
    local alg="ML-DSA-${level}"
    local server_jks="${OUT_DIR}/server-mldsa${level}.jks"
    local ca_jks="${OUT_DIR}/ca-mldsa${level}.jks"
    local work="/tmp/_pqc_$$_${level}"

    echo "=== Generating ML-DSA-${level} cert chain (root + server) ==="

    rm -f "$server_jks" "$ca_jks"
    mkdir -p "$work"

    # 1. Root CA self-signed
    "$KT" -genkeypair -keyalg "$alg" \
        -alias "root-mldsa${level}" \
        -keystore "$work/root.jks" -storepass "$PASSWD" \
        -keypass "$PASSWD" -storetype JKS \
        -dname "CN=ML-DSA-${level} Root CA, O=wolfSSL, C=US" \
        -ext "bc:c=ca:true" -validity 3650

    # 2. Server keypair (initially self-signed)
    "$KT" -genkeypair -keyalg "$alg" \
        -alias "server-mldsa${level}" \
        -keystore "$server_jks" -storepass "$PASSWD" \
        -keypass "$PASSWD" -storetype JKS \
        -dname "CN=ML-DSA-${level} server, O=wolfSSL, C=US" \
        -ext "san=dns:example.com,ip:127.0.0.1" -validity 3650

    # 3. Generate a CSR from the server keystore
    "$KT" -certreq -alias "server-mldsa${level}" \
        -keystore "$server_jks" -storepass "$PASSWD" \
        -file "$work/server.csr"

    # 4. Sign the CSR with the root CA
    "$KT" -gencert -alias "root-mldsa${level}" \
        -keystore "$work/root.jks" -storepass "$PASSWD" \
        -infile "$work/server.csr" -outfile "$work/server.crt" \
        -ext "san=dns:example.com,ip:127.0.0.1" -validity 3650

    # 5. Export the root cert
    "$KT" -exportcert -alias "root-mldsa${level}" \
        -keystore "$work/root.jks" -storepass "$PASSWD" \
        -file "$work/root.crt"

    # 6. Import root into server.jks first (so CA-signed import works)
    "$KT" -importcert -noprompt -trustcacerts \
        -alias "root-mldsa${level}" \
        -keystore "$server_jks" -storepass "$PASSWD" \
        -file "$work/root.crt"

    # 7. Replace server's self-signed cert with the CA-signed one,
    #    forming a real chain inside the keystore
    "$KT" -importcert -noprompt -alias "server-mldsa${level}" \
        -keystore "$server_jks" -storepass "$PASSWD" \
        -file "$work/server.crt"

    # 8. Build the truststore JKS (root cert only)
    "$KT" -importcert -noprompt -trustcacerts \
        -alias "root-mldsa${level}" \
        -keystore "$ca_jks" -storepass "$PASSWD" \
        -file "$work/root.crt"

    rm -rf "$work"
}

gen_jks 44
gen_jks 65
gen_jks 87

echo ""
echo "=== Done. Generated JKS files: ==="
ls -1 "$OUT_DIR"/server-mldsa*.jks "$OUT_DIR"/ca-mldsa*.jks 2>/dev/null

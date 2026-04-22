
# wolfSSL JNI Examples

This directory contains examples for the wolfSSL thin JNI wrapper. To view
examples for the wolfSSL JSSE provider, look in the
[./examples/provider](./provider) directory.

Examples should be run from the package root directory, and using the provided
wrapper scripts. The wrapper scripts set up the correct environment variables
for use with the wolfjni jar included in the wolfssljni package.

## Notes on Debug and Logging

wolfJSSE debug logging can be enabled by using `-Dwolfjsse.debug=true` at
runtime.

wolfSSL native debug logging can be enabled by using `-Dwolfssl.debug=true` at
runtime, if native wolfSSL has been compiled with `--enable-debug`.

JDK debug logging can be enabled using the `-Djavax.net.debug=all` option.

## wolfSSL JNI Example Client and Server

Example client/server applications that use wolfSSL JNI:

**Server.java** - Example wolfSSL JNI server \
**Client.java** - Example wolfSSL JNI client

These examples can be run with the provided bash scripts:

```
$ cd <wolfssljni_root>
$ ./examples/server.sh <options>
$ ./examples/client.sh <options>
```

To view usage and available options for the examples, use the `-?`
argument:

```
$ ./examples/server.sh --help
```

## wolfSSL JNI Example Simple Threaded Client and Server

Example client/server applications that use threads, which use
wolfSSL JNI (not JSSE):

**SimpleThreadedClient.java** - Example wolfSSL JNI threaded client \
**SimpleThreadedServer.java** - Example wolfSSL JNI threaded server

These examples can be run with the provided bash scripts:

```
$ cd <wolfssljni_root>
$ ./examples/SimpleThreadedServer.sh
$ ./examples/SimpleThreadedClient.sh -n <num_connections>
```

The `SimpleThreadedServer.java` starts at `localhost:11111` and waits for
client connections. When a client connection is received, it is handled in a
separate thread.

The `SimpleThreadedClient.java` makes concurrent client connections to a server
located at `localhost:11111`. Default number of client threads is **5**, but
can be changed using the `-n <num_connections>` command line argument. This
example implements a simple application-wide Java client cache where native
`WOLFSSL_SESSION` pointers are stored and used for session resumption where
possible. See code comments for further explanation.

## X509v3 Certificate Generation Example

An example is included which will generate self-signed and CA-signed
X.509v3 certificates using the wolfSSL JNI library `WolfSSLCertificate`
class.

**X509v3CertificateGeneration.java** - Certificate generation example

This example is compiled when the `ant examples` target is executed, and can
be run afterwards with the provided bash script:

```
$ cd <wolfssljni_root>
$ ./examples/X509v3CertificateGeneration.sh
```

This will write out generated certificates to the following directory:

```
examples/certs/generated/
```

## Certificate Signing Request (CSR) Generation Example

An example is included which will generate Certificate Signing Requests (CSR)
using the wolfSSL JNI library `WolfSSLCertRequest` class.

**X509CertRequest.java** - CSR generation example

This example is compiled when the `ant examples` target is executed, and can
be run afterwards with the provided bash script:

```
$ cd <wolfssljni_root>
$ ./examples/X509CertRequest.sh
```

This will write out generated CSRs to the following directory:

```
examples/certs/generated/
```

## Post Quantum (ML-KEM, ML-DSA) with ServerJSSE / ClientJSSE

wolfJSSE supports TLS 1.3 post-quantum key exchange (ML-KEM / FIPS 203) and
post quantum certificate authentication (ML-DSA / FIPS 204) when native wolfSSL
has been built with `--enable-mlkem` and `--enable-mldsa`. To additionally
enable the pure (non-hybrid) `ML-KEM-512` / `ML-KEM-768` / `ML-KEM-1024` named
groups, native wolfSSL also needs `--enable-tls-mlkem-standalone`; without it
the PQ/T hybrid groups (e.g. `X25519MLKEM768`, `SECP384R1MLKEM1024`) still
work but the standalone groups are rejected at the native layer.

**Native wolfSSL version requirement (ML-DSA cert auth):** the ML-DSA cert
authentication path requires native wolfSSL containing PR
[#10310](https://github.com/wolfSSL/wolfssl/pull/10310), which added ML-DSA
SPKI / PKCS#8 DER support to `d2i_PUBKEY` / `d2i_PrivateKey`. That PR landed
after the wolfSSL 5.9.1 release tag, so a post-5.9.1 stable release is required.
The ML-KEM key-exchange path works fine on 5.9.1, only ML-DSA cert auth is
gated. On older native wolfSSL the handshake will fail with an
`SSLHandshakeException` (typically `error code: -125` on the verifier side and
`-313` on the peer).

The `ServerJSSE.sh` and `ClientJSSE.sh` examples can use the `-pqc <alg>`
option to specify a PQC named group for TLS 1.3 handshakes.

A PQC TLS 1.3 handshake can mix and match two independent pieces:

  1. **Key exchange** -- pass `-pqc <named-group>` to use a post-quantum or
     PQ/T-hybrid named group instead of the classical default.
  2. **Certificate authentication** -- pass `-c` and/or `-A` to load ML-DSA
     entity keys and roots instead of the classical defaults
     (`server.jks` / `client.jks` / `ca-server.jks` / `ca-client.jks`).

The three subsections below show each common combination. All three
require `-v 4` (TLS 1.3).

### PQ-Hybrid Key Exchange with Classical Certs

To use classical RSA/ECDSA certs and only switch the key exchange to a PQ/T
hybrid group:

```
$ cd <wolfssljni_root>
$ ./examples/provider/ServerJSSE.sh -v 4 -pqc X25519MLKEM768
$ ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -v 4 -pqc X25519MLKEM768
```

Other supported `-pqc` named groups (build flag dependent) include:

  - **Pure ML-KEM (standalone, requires `--enable-tls-mlkem-standalone`):**
    `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`.
  - **PQ/T hybrids (default with `--enable-mlkem`):** `SECP256R1MLKEM768`,
    `SECP384R1MLKEM1024` (CNSA 2.0 level), plus the OQS-assigned hybrids
    `SECP256R1MLKEM512`, `SECP384R1MLKEM768`, `SECP521R1MLKEM1024`,
    `X25519MLKEM512`, `X448MLKEM768`.

See `./examples/provider/ServerJSSE.sh -?` for the full list at runtime.

### ML-DSA Server Cert Authentication

To replace the classical server cert with an ML-DSA cert, pass an ML-DSA
keystore via `-c` (entity cert/key) on the server, and the matching truststore
via `-A` (trusted CA) on the client. The client still uses the default
classical `client.jks` for client auth:

```
$ ./examples/provider/ServerJSSE.sh -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384 \
      -c "../provider/server-mldsa87.jks:wolfSSL test"
$ ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384 \
      -A "../provider/ca-mldsa87.jks:wolfSSL test"
```

### Mutual ML-DSA Authentication

For mutual authentication with ML-DSA certs, ServerJSSE verifies the client
by default, so just add `-c client-mldsa<N>.jks` on the client and the shared
truststore (`-A ca-mldsa<N>.jks`) on both sides:

```
$ ./examples/provider/ServerJSSE.sh -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384 \
      -c "../provider/server-mldsa87.jks:wolfSSL test" \
      -A "../provider/ca-mldsa87.jks:wolfSSL test"
$ ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384 \
      -c "../provider/client-mldsa87.jks:wolfSSL test" \
      -A "../provider/ca-mldsa87.jks:wolfSSL test"
```

### Example Keystores

Example ML-DSA keystores can be found under `examples/provider/`:
`server-mldsa{44,65,87}.jks`, `client-mldsa{44,65,87}.jks`, and
`ca-mldsa{44,65,87}.jks` (password `wolfSSL test`). The server and client
entity certs at each level are signed by the same root, so a single
`ca-mldsa<N>.jks` truststore validates both sides.

JKS paths in the examples above are relative to the wrapper's working
directory (`examples/build/`). Loading the ML-DSA private keys from a JKS
requires JDK 24 or newer (JEP 497). To regenerate the keystores, run
`./examples/provider/update-keystore-pqc.sh` (also requires JDK 24+).

### CNSA 2.0 Compliance

CNSA 2.0 (NSA Commercial National Security Algorithm Suite 2.0) mandates
TLS 1.3 + ML-KEM-1024 (or a hybrid containing it) + AES-256-GCM + ML-DSA-87
cert auth. The "Mutual ML-DSA Authentication" example above (level **87**,
`SECP384R1MLKEM1024`, `TLS_AES_256_GCM_SHA384`) is the full CNSA 2.0
recipe.

## Support

Please contact the wolfSSL support team at support@wolfssl.com with any
questions or feedback.


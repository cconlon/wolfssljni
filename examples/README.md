
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

wolfJSSE supports TLS 1.3 post-quantum key exchange (ML-KEM, FIPS 203) and
post quantum certificate authentication (ML-DSA, FIPS 204) when native wolfSSL
has been built with `--enable-mlkem` and `--enable-mldsa`. The `ServerJSSE.sh`
and `ClientJSSE.sh` examples can use the `-pqc <alg>` option to specify a PQC
named group for TLS 1.3 handshakes.

### PQC TLS 1.3 Handshake

Uses classical certs (`server.jks` / `client.jks`) but a hybrid PQ/T
key exchange named group. `X25519MLKEM768` is the hybrid that Chrome
and Chromium ship.

To use a PQC named group with the example JSSE client/server, using classical
certs (`server.jks` / `client.jks`) but a hybrid PQ/T key exchange named group,
run: `X25519MLKEM768` is a hybrid that uses X25519 + ML-KEM-768.

```
$ cd <wolfssljni_root>
$ ./examples/provider/ServerJSSE.sh -v 4 -pqc X25519MLKEM768
$ ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -v 4 -pqc X25519MLKEM768
```

Other supported `-pqc` named groups (build flag dependent) could include:
`ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`, `SECP256R1MLKEM768`,
`SECP384R1MLKEM1024` (CNSA 2.0 level), plus the OQS-assigned hybrids
`SECP256R1MLKEM512`, `SECP384R1MLKEM768`, `SECP521R1MLKEM1024`,
`X25519MLKEM512`, `X448MLKEM768`. See
`./examples/provider/ServerJSSE.sh -?` for the full list at runtime.

### CNSA 2.0 Compliance

CNSA 2.0 (NSA Commercial National Security Algorithm Suite 2.0) mandates
TLS 1.3 + ML-KEM-1024 + AES-256-GCM + ML-DSA-87 cert auth.
Setting key exchange and cipher portions in the examples would be similar
to:

```
$ ./examples/provider/ServerJSSE.sh -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384
$ ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384
```

For certificate authentication (loading an ML-DSA-87 cert into the server and
trusting it on the client), pass an ML-DSA JKS via `-c` (server cert/key) and
`-A` (trusted CA). Example keystores are located under `examples/provider/`:
`server-mldsa{44,65,87}.jks` and `ca-mldsa{44,65,87}.jks` (password
`wolfSSL test`). Loading the ML-DSA private keys from a JKS requires JDK 24
or newer (JEP 497).

Full CNSA 2.0 stack (ML-KEM-1024 hybrid + AES-256-GCM + ML-DSA-87 cert).
JKS paths are resolved relative to the wrapper's working directory
(`examples/build/`).

```
$ ./examples/provider/ServerJSSE.sh -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384 \
      -c "../provider/server-mldsa87.jks:wolfSSL test"
$ ./examples/provider/ClientJSSE.sh -h 127.0.0.1 -v 4 \
      -pqc SECP384R1MLKEM1024 -l TLS_AES_256_GCM_SHA384 \
      -A "../provider/ca-mldsa87.jks:wolfSSL test"
```

## Support

Please contact the wolfSSL support team at support@wolfssl.com with any
questions or feedback.


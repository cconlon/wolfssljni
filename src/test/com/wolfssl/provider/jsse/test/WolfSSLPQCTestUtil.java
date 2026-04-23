/* WolfSSLPQCTestUtil.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jsse.test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * Test helper for wolfJSSE PQC (ML-DSA) certificate scenarios.
 *
 * Avoids JCE KeyFactory entirely for ML-DSA private keys, which lets the same
 * test run on Java 8 (where JEP 497 ML-DSA support is absent) as well as
 * JDK 24+. Used by WolfSSLPQCAuthenticationTest and WolfSSLCNSA2Test.
 *
 * Approach: bypass standard JCE KeyStore for the private key half of the test
 * fixtures. Cert-only trust stores work on Java 8 via standard KeyStore (X.509
 * parsing is OID-tolerant). Only the private key extraction would normally
 * fail, so this util wraps PKCS#8 DER bytes in a custom PrivateKey that
 * returns the bytes verbatim to wolfJSSE, which forwards them to native
 * wolfSSL for actual ML-DSA processing.
 *
 * Once wolfcryptjni WolfSSLKeyStore (WKS) gains ML-DSA branches, WKS becomes
 * the recommended cross-version path for users. It will handle ML-DSA opaquely
 * without requiring JDK 24+ or custom KeyManagers.
 */
class WolfSSLPQCTestUtil {

    /** Default location of generated ML-DSA cert chains. */
    static final String PQC_CERT_DIR = "examples/certs/pqc";

    private WolfSSLPQCTestUtil() {
    }

    /**
     * Build a one-entry X509KeyManager from a PEM cert file and a PEM PKCS#8
     * private key file. The certificate file may contain a single cert/chain.
     *
     * @param alias       alias to surface from the KeyManager
     * @param certPemPath path to the PEM cert (or chain)
     * @param keyPemPath  path to the PEM PKCS#8 private key
     * @param algorithm   advertised algorithm name, e.g. "ML-DSA-87"
     * @return KeyManager array suitable for SSLContext.init()
     */
    static KeyManager[] keyManagerFromPem(String alias, String certPemPath,
        String keyPemPath, String algorithm) throws Exception {

        X509Certificate[] chain = loadCertChain(certPemPath);
        byte[] pkcs8 = pemFileToDer(keyPemPath);

        PrivateKey key = new PemPrivateKey(pkcs8, algorithm);

        return new KeyManager[] {
            new SinglePemKeyManager(alias, chain, key)
        };
    }

    /**
     * Build a TrustManager array containing only the supplied root cert as a
     * trusted CA. Uses an in-memory JKS-format KeyStore, no private keys,
     * so this works on Java 8 even when the trusted cert is signed with ML-DSA
     * (cert-only entries don't trigger KeyFactory on load).
     *
     * @param rootCertPemPath path to the trusted root cert PEM
     * @return TrustManager array suitable for SSLContext.init()
     */
    static TrustManager[] trustManagerFromPem(String rootCertPemPath)
        throws Exception {

        X509Certificate[] chain = loadCertChain(rootCertPemPath);
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null, null);
        for (int i = 0; i < chain.length; i++) {
            ks.setCertificateEntry("trust-" + i, chain[i]);
        }

        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance("SunX509", "wolfJSSE");
        tmf.init(ks);

        return tmf.getTrustManagers();
    }

    /* Resolve a path relative to the repo root, similar to what
     * WolfSSLTestFactory.getPath() does, so tests work whether run from the
     * repo root or from a build subdirectory. */
    static String resolveRepoPath(String relative) {

        if (new File(relative).exists()) {
            return relative;
        }

        File f = new File("..", relative);
        if (f.exists()) {
            return f.getPath();
        }
        f = new File("../..", relative);
        if (f.exists()) {
            return f.getPath();
        }

        return relative;
    }

    /* Returns true if the given PQC cert file exists at the resolved test-time
     * path. Tests use this to skip cleanly when the cert generation step
     * (gen-mldsa-certs.sh) has not been run. */
    static boolean pqcCertExists(String relative) {
        String path = resolveRepoPath(relative);
        return new File(path).isFile();
    }

    private static X509Certificate[] loadCertChain(String pemPath)
        throws Exception {

        FileInputStream in = new FileInputStream(resolveRepoPath(pemPath));
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            java.util.Collection<? extends Certificate> certs =
                cf.generateCertificates(in);

            return certs.toArray(new X509Certificate[0]);

        } finally {
            in.close();
        }
    }

    /* Strip "-----BEGIN ...-----" / "-----END ...-----" markers and
     * surrounding whitespace, base64-decode the inner body. */
    private static byte[] pemFileToDer(String pemPath) throws IOException {

        File f = new File(resolveRepoPath(pemPath));
        byte[] all = new byte[(int) f.length()];
        FileInputStream in = new FileInputStream(f);
        try {
            int off = 0;
            int n;
            while ((n = in.read(all, off, all.length - off)) > 0) {
                off += n;
            }
        } finally {
            in.close();
        }

        String pem = new String(all, "UTF-8");
        StringBuilder b64 = new StringBuilder();
        for (String line : pem.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("-----")) {
                continue;
            }
            b64.append(t);
        }

        return Base64.getDecoder().decode(b64.toString());
    }

    /**
     * Custom PrivateKey that just stores PKCS#8 DER bytes and returns them
     * verbatim. wolfJSSE forwards getEncoded() bytes to native wolfSSL via
     * wolfSSL_use_PrivateKey_buffer, which handles all algorithm-specific
     * parsing in C, so the JDK never needs its own ML-DSA KeyFactory.
     */
    private static final class PemPrivateKey implements PrivateKey {

        private static final long serialVersionUID = 1L;

        private final byte[] encoded;
        private final String algorithm;

        PemPrivateKey(byte[] pkcs8, String algorithm) {
            this.encoded = pkcs8.clone();
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public String getFormat() {
            return "PKCS#8";
        }

        public byte[] getEncoded() {
            return encoded.clone();
        }
    }

    /**
     * Single-entry X509KeyManager. Returns the one alias for any keyType /
     * issuer query. Callers create a new instance per test fixture, so there's
     * no ambiguity to resolve.
     */
    private static final class SinglePemKeyManager implements X509KeyManager {

        private final String alias;
        private final X509Certificate[] chain;
        private final PrivateKey key;
        private final String[] aliases;

        SinglePemKeyManager(String alias, X509Certificate[] chain,
            PrivateKey key) {
            this.alias = alias;
            this.chain = chain.clone();
            this.key = key;
            this.aliases = new String[] { alias };
        }

        public String chooseClientAlias(String[] keyTypes,
            Principal[] issuers, Socket socket) {
            return alias;
        }

        public String chooseServerAlias(String keyType,
            Principal[] issuers, Socket socket) {
            return alias;
        }

        public X509Certificate[] getCertificateChain(String a) {
            return alias.equals(a) ? chain.clone() : null;
        }

        public String[] getClientAliases(String keyType,
            Principal[] issuers) {
            return aliases.clone();
        }

        public PrivateKey getPrivateKey(String a) {
            return alias.equals(a) ? key : null;
        }

        public String[] getServerAliases(String keyType,
            Principal[] issuers) {
            return aliases.clone();
        }
    }
}

/* WolfSSLPQCTestUtil.java
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;

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

    /** Security property holding the global supported-curves list. */
    static final String CURVES_PROP = "wolfjsse.enabledSupportedCurves";

    /**
     * Process-global lock guarding the wolfjsse.enabledSupportedCurves
     * Security property (and any related global named-groups properties).
     *
     * The property is JVM-global state read per-handshake by wolfJSSE, so
     * tests that set it must serialize against each other. Callers MUST
     * synchronize on this lock around the whole
     * set / use (handshake) / restore sequence, e.g.:
     *
     *   synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
     *       String prev = WolfSSLPQCTestUtil.setCurvesProperty("...");
     *       try {
     *           ... run handshake ...
     *       } finally {
     *           WolfSSLPQCTestUtil.restoreCurvesProperty(prev);
     *       }
     *   }
     */
    public static final Object GROUP_PROP_LOCK = new Object();

    /**
     * Set the wolfjsse.enabledSupportedCurves Security property and return
     * the previous value, for later restore via restoreCurvesProperty().
     *
     * Caller must hold GROUP_PROP_LOCK across set / use / restore.
     *
     * @param value new property value, or null to clear (Security
     *              properties cannot be removed, so null sets "")
     * @return previous property value, possibly null if never set
     */
    public static String setCurvesProperty(String value) {
        String prev = Security.getProperty(CURVES_PROP);
        Security.setProperty(CURVES_PROP, (value == null) ? "" : value);
        return prev;
    }

    /**
     * Restore the wolfjsse.enabledSupportedCurves Security property to a
     * value previously returned by setCurvesProperty(). Java Security
     * properties cannot be removed once set, so a null previous value is
     * restored as the empty string, which wolfJSSE treats as unset.
     *
     * Caller must hold GROUP_PROP_LOCK across set / use / restore.
     *
     * @param prev previous property value returned by setCurvesProperty()
     */
    public static void restoreCurvesProperty(String prev) {
        Security.setProperty(CURVES_PROP, (prev == null) ? "" : prev);
    }

    /** System property holding the JDK global named-groups list. */
    static final String JDK_GROUPS_PROP = "jdk.tls.namedGroups";

    /**
     * Set the jdk.tls.namedGroups System property and return the previous
     * value, for later restore via restoreJdkNamedGroupsProperty().
     *
     * Caller must hold GROUP_PROP_LOCK across set / use / restore.
     *
     * @param value new property value, or null to clear the property
     * @return previous property value, or null if the property was unset
     */
    public static String setJdkNamedGroupsProperty(String value) {
        String prev = System.getProperty(JDK_GROUPS_PROP);
        if (value == null) {
            System.clearProperty(JDK_GROUPS_PROP);
        }
        else {
            System.setProperty(JDK_GROUPS_PROP, value);
        }
        return prev;
    }

    /**
     * Restore the jdk.tls.namedGroups System property to a value
     * previously returned by setJdkNamedGroupsProperty(). Unlike Security
     * properties, System properties can be removed, so a null previous
     * value clears the property.
     *
     * Caller must hold GROUP_PROP_LOCK across set / use / restore.
     *
     * @param prev previous value from setJdkNamedGroupsProperty()
     */
    public static void restoreJdkNamedGroupsProperty(String prev) {
        if (prev == null) {
            System.clearProperty(JDK_GROUPS_PROP);
        }
        else {
            System.setProperty(JDK_GROUPS_PROP, prev);
        }
    }

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

    /* Resolve a path relative to the repo root, similar to how
     * WolfSSLTestFactory's constructor probes alternate locations (see
     * WolfSSLTestFactory.isIDEFile() / setPaths()), so tests work whether
     * run from the repo root, a build subdirectory, or the IDE layout. */
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
        /* IDE layout, same escape prefix WolfSSLTestFactory.isIDEFile()
         * probes for its KeyStore files. */
        f = new File("../../..", relative);
        if (f.exists()) {
            return f.getPath();
        }

        /* Android instrumented-test location. */
        f = new File("/data/local/tmp", relative);
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

    /* Cached probe result. null = not yet probed. */
    private static Boolean nativeMlDsaCertParsingSupported = null;

    /**
     * Returns true if native wolfSSL can parse an ML-DSA X.509 certificate.
     * Drives test SKIP decisions for ML-DSA cert-auth tests so they pass
     * cleanly on older native wolfSSL.
     *
     * wolfJSSE's ML-DSA cert-auth path needs native wolfSSL PR #10310,
     * which added ML-DSA SPKI / PKCS#8 DER support to d2i_PUBKEY /
     * d2i_PrivateKey. That PR landed after the 5.9.1 release tag, so 5.9.1
     * (and earlier) cannot process ML-DSA certs while master and post-5.9.1
     * stable releases can.
     *
     * The probe loads the DER bytes of the generated ML-DSA-44 server cert
     * and parses them directly with native wolfSSL via WolfSSLCertificate,
     * then queries the signature type. This probes the native capability
     * only, without running a wolfJSSE handshake, so a wolfJSSE-level
     * regression can no longer silently convert the gated tests into skips:
     * if native support is present but the wolfJSSE handshake path breaks,
     * the gated tests now FAIL instead of being skipped.
     */
    static synchronized boolean nativeMlDsaCertParsingSupported() {

        if (nativeMlDsaCertParsingSupported != null) {
            return nativeMlDsaCertParsingSupported.booleanValue();
        }

        if (!WolfSSL.MLDSAEnabled()) {
            nativeMlDsaCertParsingSupported = Boolean.FALSE;
            return false;
        }

        String serverCertDer = PQC_CERT_DIR + "/server-mldsa44.der";

        if (!pqcCertExists(serverCertDer)) {
            /* Cert missing. Treat as unsupported so tests are skipped. */
            nativeMlDsaCertParsingSupported = Boolean.FALSE;
            return false;
        }

        WolfSSLCertificate cert = null;
        try {
            byte[] der = readFileBytes(resolveRepoPath(serverCertDer));
            cert = new WolfSSLCertificate(der, WolfSSL.SSL_FILETYPE_ASN1);
            String sigType = cert.getSignatureType();
            nativeMlDsaCertParsingSupported =
                (sigType != null) ? Boolean.TRUE : Boolean.FALSE;

        } catch (WolfSSLException | IOException e) {
            /* Native failed to parse the ML-DSA cert DER. */
            nativeMlDsaCertParsingSupported = Boolean.FALSE;

        } finally {
            if (cert != null) {
                cert.free();
            }
        }

        return nativeMlDsaCertParsingSupported.booleanValue();
    }

    /** Skip message used by all tests that gate on the probe. Centralized
     *  so the wolfSSL version / PR reference stays consistent. */
    static final String MLDSA_CERT_PARSING_SKIP_MSG =
        "Native wolfSSL lacks ML-DSA X.509 certificate parsing support " +
        "(requires post-5.9.1 release with wolfSSL PR #10310)";

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

    /* Read the full contents of a file into a byte array. */
    private static byte[] readFileBytes(String path) throws IOException {

        File f = new File(path);
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

        return all;
    }

    /* Strip "-----BEGIN ...-----" / "-----END ...-----" markers and
     * surrounding whitespace, base64-decode the inner body. */
    private static byte[] pemFileToDer(String pemPath) throws IOException {

        byte[] all = readFileBytes(resolveRepoPath(pemPath));

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

        private final transient byte[] encoded;
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

        /* PrivateKey extends Serializable. This test only key wrapper holds
         * raw PKCS#8 private key material and must never end up on a
         * serialization stream. */
        private void writeObject(ObjectOutputStream out)
            throws IOException {
            throw new NotSerializableException(
                "PemPrivateKey is a test wrapper around raw private key " +
                "material and must not be serialized");
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

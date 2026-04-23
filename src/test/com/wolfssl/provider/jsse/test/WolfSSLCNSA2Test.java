/* WolfSSLCNSA2Test.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Composite CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)
 * compliance test.
 *   - TLS 1.3 only
 *   - Key exchange: SECP384R1MLKEM1024 (ML-KEM-1024 hybrid w/ classical
 *     bridge, the highest-security ML-KEM parameter set per FIPS 203)
 *   - Authentication: ML-DSA-87 X.509 certificates (FIPS 204 Cat 5)
 *   - Cipher suite: TLS_AES_256_GCM_SHA384 (mandated by CNSA 2.0)
 *
 * Skipped when native wolfSSL was not built with --enable-mlkem or
 * --enable-mldsa, when TLS 1.3 is not compiled in, or when the
 * gen-mldsa-certs.sh PEM artifacts are absent.
 */
public class WolfSSLCNSA2Test {

    private static final String PROVIDER = "wolfJSSE";
    private static final String CURVES_PROP = "wolfjsse.enabledSupportedCurves";

    private static final String SERVER_CERT =
        "examples/certs/pqc/server-mldsa87.pem";
    private static final String SERVER_KEY =
        "examples/certs/pqc/server-mldsa87-priv.pem";
    private static final String ROOT_CERT =
        "examples/certs/pqc/root-mldsa87.pem";

    /* Process-global lock around wolfjsse.enabledSupportedCurves */
    private static final Object curvesPropLock = new Object();

    private static WolfSSLTestFactory tf;

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLCNSA2 Class");

        Security.insertProviderAt(new WolfSSLProvider(), 1);
        tf = new WolfSSLTestFactory();
    }

    @Test
    public void testCNSA2_FullStack() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.MLDSAEnabled() &&
            WolfSSL.TLSv13Enabled());
        Assume.assumeTrue(
            "PQC cert PEM missing; run gen-mldsa-certs.sh first",
            WolfSSLPQCTestUtil.pqcCertExists(ROOT_CERT));

        synchronized (curvesPropLock) {
            String prevCurves = Security.getProperty(CURVES_PROP);
            try {
                /* Restrict supported_groups to ML-KEM-1024 hybrid (CNSA 2.0
                 * level). With no classical fallback in the list, a
                 * successful handshake proves PQC kex actually happened. */
                Security.setProperty(CURVES_PROP, "SECP384R1MLKEM1024");

                KeyManager[] serverKm = WolfSSLPQCTestUtil.keyManagerFromPem(
                    "server-mldsa87", SERVER_CERT, SERVER_KEY, "ML-DSA-87");
                TrustManager[] clientTm =
                    WolfSSLPQCTestUtil.trustManagerFromPem(ROOT_CERT);

                SSLContext serverCtx = tf.createSSLContext("TLSv1.3",
                    PROVIDER, null, serverKm);
                SSLContext clientCtx = tf.createSSLContext("TLSv1.3",
                    PROVIDER, clientTm, null);

                SSLEngine server = serverCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                /* Restrict to the CNSA-mandated cipher suite. */
                server.setEnabledCipherSuites(
                    new String[] { "TLS_AES_256_GCM_SHA384" });

                SSLEngine client = clientCtx.createSSLEngine(
                    "wolfSSL CNSA2 test", 11111);
                client.setUseClientMode(true);
                client.setEnabledCipherSuites(
                    new String[] { "TLS_AES_256_GCM_SHA384" });

                int ret = tf.testConnection(server, client,
                    new String[] { "TLS_AES_256_GCM_SHA384" },
                    new String[] { "TLSv1.3" }, "CNSA 2.0 test");
                assertEquals("CNSA 2.0 handshake should succeed", 0, ret);

                /* Confirm post-handshake session attributes match the
                 * CNSA 2.0 mandate. */
                SSLSession sess = client.getSession();
                assertEquals("TLS protocol must be TLSv1.3",
                    "TLSv1.3", sess.getProtocol());
                assertEquals("Cipher suite must be TLS_AES_256_GCM_SHA384",
                    "TLS_AES_256_GCM_SHA384", sess.getCipherSuite());

            } finally {
                if (prevCurves == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prevCurves);
                }
            }
        }
    }

    /**
     * Negative case: client that asks only for non-CNSA cipher suites
     * (TLS 1.2-only suites) against a TLS 1.3 server should fail. This
     * sanity checks that we are not silently downgrading to non-CNSA
     * cipher suites or protocols.
     */
    @Test
    public void testCNSA2_NoFallbackToTls12() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.MLDSAEnabled() &&
            WolfSSL.TLSv13Enabled());
        Assume.assumeTrue(
            "PQC cert PEM missing; run gen-mldsa-certs.sh first",
            WolfSSLPQCTestUtil.pqcCertExists(ROOT_CERT));

        synchronized (curvesPropLock) {
            String prevCurves = Security.getProperty(CURVES_PROP);
            try {
                Security.setProperty(CURVES_PROP, "SECP384R1MLKEM1024");

                KeyManager[] serverKm = WolfSSLPQCTestUtil.keyManagerFromPem(
                    "server-mldsa87", SERVER_CERT, SERVER_KEY, "ML-DSA-87");
                TrustManager[] clientTm =
                    WolfSSLPQCTestUtil.trustManagerFromPem(ROOT_CERT);

                SSLContext serverCtx = tf.createSSLContext("TLSv1.3",
                    PROVIDER, null, serverKm);
                SSLContext clientCtx = tf.createSSLContext("TLSv1.3",
                    PROVIDER, clientTm, null);

                SSLEngine server = serverCtx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                /* Server only offers CNSA cipher. */
                server.setEnabledCipherSuites(
                    new String[] { "TLS_AES_256_GCM_SHA384" });

                SSLEngine client = clientCtx.createSSLEngine(
                    "wolfSSL CNSA2 test", 11111);
                client.setUseClientMode(true);
                /* Client tries to force a TLS 1.2-only suite -- no
                 * common ground with TLS 1.3-locked server, expect
                 * handshake failure. */
                String[] tls12OnlySuites = client.getSupportedCipherSuites();
                String picked = null;
                for (String s : tls12OnlySuites) {
                    if (s.startsWith("TLS_ECDHE_") ||
                        s.startsWith("TLS_RSA_")) {
                        picked = s;
                        break;
                    }
                }
                Assume.assumeNotNull(picked);
                client.setEnabledCipherSuites(new String[] { picked });

                int ret = tf.testConnection(server, client,
                    null, new String[] { "TLSv1.3" }, "CNSA 2.0 test");
                assertTrue("Handshake must fail when client refuses CNSA " +
                    "cipher suite (no downgrade allowed), got ret = " + ret,
                    ret != 0);

            } finally {
                if (prevCurves == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prevCurves);
                }
            }
        }
    }
}

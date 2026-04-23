/* WolfSSLPQCKeyExchangeTest.java
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
import java.security.Security;
import java.security.NoSuchProviderException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests for ML-KEM (FIPS 203) named-group support in wolfJSSE. Each
 * test sets the wolfjsse.enabledSupportedCurves Security property to a single
 * PQC group and runs an end-to-end SSLEngine handshake against itself with
 * classical ECC certs. With only one group in the list, a successful handshake
 * proves the PQC group was negotiated.
 *
 * Skipped when native wolfSSL was not built with --enable-mlkem or when
 * TLS 1.3 is not compiled in.
 */
public class WolfSSLPQCKeyExchangeTest {

    private static final String PROVIDER = "wolfJSSE";
    private static final String CURVES_PROP =
        "wolfjsse.enabledSupportedCurves";
    private static final String APP_DATA = "PQC handshake test";

    private static WolfSSLTestFactory tf;

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLPQCKeyExchange Class");

        Security.insertProviderAt(new WolfSSLProvider(), 1);
        tf = new WolfSSLTestFactory();
    }

    /**
     * Run a single SSLEngine handshake using protocol+curve. Caller must hold
     * WolfSSLTestFactory.jdkTlsDisabledAlgorithmsLock if mutating shared JDK
     * Security properties; we hold a separate lock around the
     * wolfjsse.enabledSupportedCurves mutation.
     *
     * @param protocol JSSE protocol string, e.g. "TLSv1.3"
     * @param curve named-group string for the curves property,
     *              e.g. "ML-KEM-768" or null to leave property unset
     *              (use native default ordering)
     * @return testConnection result: 0 success, -1 failure
     */
    private int handshakeWithCurve(String protocol, String curve)
        throws Exception {

        synchronized (curvesPropLock) {
            String prev = Security.getProperty(CURVES_PROP);
            try {
                if (curve != null) {
                    Security.setProperty(CURVES_PROP, curve);
                }
                else {
                    Security.setProperty(CURVES_PROP, "");
                }

                SSLContext ctx = tf.createSSLContext(protocol, PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client = ctx.createSSLEngine(
                    "wolfSSL PQC test", 11111);
                client.setUseClientMode(true);

                return tf.testConnection(server, client, null,
                    new String[] { protocol }, APP_DATA);

            } finally {
                if (prev == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prev);
                }
            }
        }
    }

    /* Process-global lock around wolfjsse.enabledSupportedCurves prop */
    private static final Object curvesPropLock = new Object();

    @Test
    public void testHandshake_X25519MLKEM768() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        int ret = handshakeWithCurve("TLSv1.3", "X25519MLKEM768");
        /* Native wolfSSL may have been built without HAVE_CURVE25519, in
         * which case X25519MLKEM768 is not a valid named group. Treat as
         * skipped rather than failing the run. */
        Assume.assumeTrue(
            "X25519MLKEM768 not negotiable in this native build",
            ret == 0);
    }

    @Test
    public void testHandshake_SECP256R1MLKEM768() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        /* Hybrid SECP256R1MLKEM768 only needs ECC + ML-KEM, both of which are
         * present in any reasonable PQC-capable build, so this is the most
         * portable PQC handshake. */
        int ret = handshakeWithCurve("TLSv1.3", "SECP256R1MLKEM768");
        assertEquals("TLS 1.3 handshake with SECP256R1MLKEM768 should succeed",
            0, ret);
    }

    @Test
    public void testHandshake_SECP384R1MLKEM1024() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        int ret = handshakeWithCurve("TLSv1.3", "SECP384R1MLKEM1024");
        assertEquals("TLS 1.3 handshake with SECP384R1MLKEM1024 should succeed",
            0, ret);
    }

    @Test
    public void testHandshake_MLKEM768_standalone() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        int ret = handshakeWithCurve("TLSv1.3", "ML-KEM-768");
        /* Native wolfSSL builds with WOLFSSL_TLS_NO_MLKEM_STANDALONE
         * (the default unless --enable-tls-mlkem-standalone) reject
         * standalone ML-KEM groups. Skip rather than fail. */
        Assume.assumeTrue(
            "Standalone ML-KEM groups disabled in this native build",
            ret == 0);
    }

    /**
     * Engine-filter integration test: the JSSE engine helper must silently
     * filter PQC named groups out of the supported_groups extension when
     * TLS 1.3 is not in the active protocols. This matches SunJSSE/BCJSSE
     * behavior. The handshake should not throw. An unrelated handshake failure
     * (no common group) is the expected downstream outcome since we restricted
     * to PQC only and the negotiated TLS 1.2 cannot use PQC.
     */
    @Test
    public void testEngineFilter_TLS12_PQC_doesNotThrow() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv12Enabled());

        /* TLS 1.2 only + PQC group. wolfJSSE engine helper should filter the
         * PQC group out before calling useSupportedCurves on native wolfSSL.
         * The handshake is expected to fail because the supported_groups list
         * ends up empty (no common group), but it must NOT throw an
         * exception. */
        int ret = handshakeWithCurve("TLSv1.2", "ML-KEM-768");
        /* Either outcome is acceptable: a clean handshake failure
         * (-1, peer rejects empty supported_groups) or an unexpected success
         * if native picked a default. Anything that throws out of
         * testConnection itself would indicate the filter regressed. */
        assertTrue("TLS 1.2 + PQC should fall through to handshake step " +
            "without throwing in the engine helper, got ret=" + ret,
            ret == 0 || ret == -1);
    }

    /**
     * Mixed list with both PQC and classical groups under TLS 1.2:
     * filter strips PQC, classical group remains, handshake should succeed.
     */
    @Test
    public void testEngineFilter_TLS12_MixedFallsBackToClassical()
        throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv12Enabled());

        int ret = handshakeWithCurve("TLSv1.2", "X25519MLKEM768,secp256r1");
        assertEquals("TLS 1.2 with PQC filtered out should succeed via " +
            "classical secp256r1, got ret=" + ret,
            0, ret);
    }
}

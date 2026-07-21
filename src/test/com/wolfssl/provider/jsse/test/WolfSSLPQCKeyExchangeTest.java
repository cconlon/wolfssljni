/* WolfSSLPQCKeyExchangeTest.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLSession;
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
     * Security properties; the shared WolfSSLPQCTestUtil.GROUP_PROP_LOCK is
     * held here around the wolfjsse.enabledSupportedCurves mutation.
     *
     * @param protocol JSSE protocol string, e.g. "TLSv1.3"
     * @param curve named-group string for the curves property,
     *              e.g. "ML-KEM-768" or null to leave property unset
     *              (use native default ordering)
     * @return testConnection result: 0 success, -1 failure
     */
    private int handshakeWithCurve(String protocol, String curve)
        throws Exception {

        synchronized (WolfSSLPQCTestUtil.GROUP_PROP_LOCK) {
            String prev = WolfSSLPQCTestUtil.setCurvesProperty(curve);
            try {
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
                WolfSSLPQCTestUtil.restoreCurvesProperty(prev);
            }
        }
    }

    /**
     * Check whether the given named group codepoint is usable in the current
     * native wolfSSL build, by creating a throwaway TLS 1.3 session and
     * trying useKeyShare(). Returns true only when native key-share generation
     * succeeds.
     */
    private static boolean isNamedGroupAvailable(int group) {

        WolfSSLContext ctx = null;
        WolfSSLSession ssl = null;

        try {
            ctx = new WolfSSLContext(WolfSSL.TLSv1_3_ClientMethod());
            ssl = new WolfSSLSession(ctx);

            return ssl.useKeyShare(group) == WolfSSL.SSL_SUCCESS;

        } catch (Throwable t) {
            return false;

        } finally {
            try {
                if (ssl != null) {
                    ssl.freeSSL();
                }
                if (ctx != null) {
                    ctx.free();
                }
            } catch (Throwable t) {
                /* cleanup, just swallow */
            }
        }
    }

    @Test
    public void testHandshake_X25519MLKEM768() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());
        /* If native wolfSSL is built without HAVE_CURVE25519, X25519MLKEM768
         * is not a valid named group. Check up front so handshake regressions
         * below show up as failure rather than a silent skip. */
        Assume.assumeTrue("X25519MLKEM768 unavailable in native build " +
            "(likely missing HAVE_CURVE25519)",
            isNamedGroupAvailable(WolfSSL.WOLFSSL_X25519MLKEM768));

        int ret = handshakeWithCurve("TLSv1.3", "X25519MLKEM768");
        assertEquals("TLS 1.3 handshake with X25519MLKEM768 should succeed",
            0, ret);
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
        /* Native wolfSSL builds with WOLFSSL_TLS_NO_MLKEM_STANDALONE
         * (default unless --enable-tls-mlkem-standalone) reject standalone
         * ML-KEM groups. Check up front so handshake regressions below
         * show up as failure, not a silent skip. */
        Assume.assumeTrue("Standalone ML-KEM-768 unavailable in native " +
            "build (likely missing --enable-tls-mlkem-standalone)",
            isNamedGroupAvailable(WolfSSL.WOLFSSL_ML_KEM_768));

        int ret = handshakeWithCurve("TLSv1.3", "ML-KEM-768");
        assertEquals("TLS 1.3 handshake with ML-KEM-768 should succeed",
            0, ret);
    }

    /**
     * Handshake coverage for the OQS-assigned hybrid codepoints. Native
     * wolfSSL only compiles these groups in when built with
     * --enable-experimental --enable-extra-pqc-hybrids (exercised by the
     * linux-zulu-pqc-experimental CI variant); on standard PQC builds
     * every group probes unavailable and this test skips. Each available
     * group must complete a TLS 1.3 handshake.
     */
    @Test
    public void testHandshake_OQSHybrids() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        String[] names = new String[] {
            "SECP256R1MLKEM512", "SECP384R1MLKEM768",
            "SECP521R1MLKEM1024", "X25519MLKEM512", "X448MLKEM768"
        };
        int available = 0;

        for (String name : names) {
            int group = WolfSSL.getNamedGroupFromString(name);
            if (!isNamedGroupAvailable(group)) {
                continue;
            }
            available++;

            int ret = handshakeWithCurve("TLSv1.3", name);
            assertEquals("TLS 1.3 handshake with " + name +
                " should succeed", 0, ret);
        }

        Assume.assumeTrue("No OQS-codepoint hybrid groups available in " +
            "native build (requires --enable-experimental " +
            "--enable-extra-pqc-hybrids)", available > 0);
    }

    /**
     * Fail-closed integration test: PQC named groups are TLS 1.3 only, so
     * wolfJSSE filters them out of the supported_groups extension when
     * TLS 1.3 is not in the active protocols. With an all-PQC
     * wolfjsse.enabledSupportedCurves list on a TLS 1.2-only session, the
     * filtered list ends up empty and wolfJSSE fails closed: handshake
     * setup throws SSLException (from setLocalParams /
     * applyToSupportedGroupsExtension) rather than silently voiding the
     * configured restriction by negotiating from native default groups.
     *
     * WolfSSLTestFactory.testConnection() catches SSLException thrown out
     * of SSLEngine wrap()/unwrap() (where handshake setup runs) and
     * converts it to a -1 return, so the fail-closed behavior surfaces
     * here as ret == -1.
     */
    @Test
    public void testFilter_TLS12_AllPQC_failsClosed() throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv12Enabled());

        int ret = handshakeWithCurve("TLSv1.2", "ML-KEM-768");
        assertEquals("TLS 1.2 with an all-PQC supported-curves list must " +
            "fail closed with SSLException during handshake setup " +
            "(surfaced by testConnection as -1), got ret=" + ret,
            -1, ret);
    }

    /**
     * Companion positive case for the fail-closed test above. Mixed list
     * with both PQC and classical groups under TLS 1.2: the PQC entry is
     * dropped (TLS 1.3 only), the classical entry still applies, and the
     * handshake succeeds via secp256r1.
     */
    @Test
    public void testFilter_TLS12_MixedFallsBackToClassical()
        throws Exception {

        Assume.assumeTrue(WolfSSL.MLKEMEnabled() && WolfSSL.TLSv12Enabled());

        int ret = handshakeWithCurve("TLSv1.2", "X25519MLKEM768,secp256r1");
        assertEquals("TLS 1.2 with PQC filtered out should succeed via " +
            "classical secp256r1, got ret=" + ret,
            0, ret);
    }
}

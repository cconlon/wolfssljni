/* WolfSSLNamedGroupsTest.java
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
import com.wolfssl.provider.jsse.WolfSSLParametersHelper;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;
import java.lang.reflect.Method;
import java.security.NoSuchProviderException;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

/**
 * Tests for SSLParameters.setNamedGroups() / getNamedGroups() integration in
 * wolfJSSE.
 *
 * Coverage:
 *   - Reflection bridge in WolfSSLParametersHelper returns null cleanly
 *     when the host JDK lacks the methods.
 *   - When present, per-engine/socket setNamedGroups() overrides the global
 *     wolfjsse.enabledSupportedCurves Security property.
 *   - getNamedGroups() round-trips through SSLEngine via reflection.
 *
 * Per-method Assume.assume* skips handle JDKs that don't expose the methods.
 */
public class WolfSSLNamedGroupsTest {

    private static final String PROVIDER = "wolfJSSE";
    private static final String CURVES_PROP = "wolfjsse.enabledSupportedCurves";
    private static final String JDK_GROUPS_PROP = "jdk.tls.namedGroups";
    private static final String APP_DATA = "named groups test";

    /* Process-global lock around the named-groups static properties. */
    private static final Object curvesPropLock = new Object();

    private static WolfSSLTestFactory tf;
    private static boolean jdkHasNamedGroups = false;

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp()
        throws NoSuchProviderException, WolfSSLException {

        System.out.println("WolfSSLNamedGroups Class");

        Security.insertProviderAt(new WolfSSLProvider(), 1);
        tf = new WolfSSLTestFactory();

        try {
            SSLParameters.class.getMethod("setNamedGroups", String[].class);
            SSLParameters.class.getMethod("getNamedGroups");
            jdkHasNamedGroups = true;

        } catch (NoSuchMethodException e) {
            jdkHasNamedGroups = false;
        }
    }

    /**
     * Reflection helper must return null cleanly when the host JDK does not
     * expose SSLParameters.set/getNamedGroups, so callers can safely fall back
     * to the Security property without special handling for the JDK version.
     */
    @Test
    public void testHelper_returnsNullWhenApiAbsent() {

        Assume.assumeFalse(
            "Host JDK has SSLParameters.setNamedGroups/getNamedGroups",
            jdkHasNamedGroups);

        SSLParameters p = new SSLParameters();
        assertNull("getNamedGroupsFromParams must return null on a JDK " +
            "without SSLParameters.getNamedGroups",
            WolfSSLParametersHelper.getNamedGroupsFromParams(p));

        /* setNamedGroupsOnParams must be a clean no-op on a JDK without
         * SSLParameters.setNamedGroups. */
        WolfSSLParametersHelper.setNamedGroupsOnParams(p,
            new String[] { "X25519MLKEM768" });
        assertNull(WolfSSLParametersHelper.getNamedGroupsFromParams(p));
    }

    /**
     * When the host JDK exposes SSLParameters.setNamedGroups, the helper  must
     * round-trip the value through reflection.
     */
    @Test
    public void testHelper_roundTripsViaReflection() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);

        SSLParameters p = new SSLParameters();
        String[] groups = new String[] {
            "X25519MLKEM768", "SecP256r1MLKEM768", "x25519"
        };

        Method setM = SSLParameters.class.getMethod("setNamedGroups",
            String[].class);
        setM.invoke(p, (Object) groups);

        String[] back = WolfSSLParametersHelper.getNamedGroupsFromParams(p);
        assertArrayEquals("Round-tripped named groups must match", groups,
            back);

        /* Mutating the returned array must not affect the stored value
         * (helper returns a clone). */
        if (back != null) {
            back[0] = "MUTATED";
            String[] back2 =
                WolfSSLParametersHelper.getNamedGroupsFromParams(p);
            assertEquals("getNamedGroupsFromParams must return a defensive " +
                "copy", "X25519MLKEM768", back2[0]);
        }
    }

    /**
     * Per SSLEngine SSLParameters.setNamedGroups() must override the global
     * wolfjsse.enabledSupportedCurves Security property and successfully
     * do a TLS 1.3 PQC handshake.
     */
    @Test
    public void testEngineHonorsPerEngineNamedGroups() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (curvesPropLock) {
            String prev = Security.getProperty(CURVES_PROP);
            try {
                /* Set a wrong group at the global property level.
                 * SSLEngine setNamedGroups should take precedence. */
                Security.setProperty(CURVES_PROP, "secp256r1");

                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                /* Apply SSLEngine override on both sides. */
                Method setM = SSLParameters.class.getMethod(
                    "setNamedGroups", String[].class);
                String[] perEngine = new String[] { "SECP256R1MLKEM768" };

                SSLParameters cp = client.getSSLParameters();
                setM.invoke(cp, (Object) perEngine);
                client.setSSLParameters(cp);

                SSLParameters sp = server.getSSLParameters();
                setM.invoke(sp, (Object) perEngine);
                server.setSSLParameters(sp);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Per-engine setNamedGroups should drive a " +
                    "successful PQC handshake", 0, ret);
            }
            finally {
                if (prev == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prev);
                }
            }
        }
    }

    /**
     * Server-side application of SSLEngine setNamedGroups. When the server
     * restricts itself to a PQC group via setNamedGroups but the client
     * offers only classical groups, the handshake must fail (no common group).
     */
    @Test
    public void testServerNamedGroupsRestriction() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (curvesPropLock) {
            String prev = Security.getProperty(CURVES_PROP);
            try {
                Security.setProperty(CURVES_PROP, "");

                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);

                /* Server restricts to PQC only. */
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                Method setM = SSLParameters.class.getMethod(
                    "setNamedGroups", String[].class);
                SSLParameters sp = server.getSSLParameters();
                setM.invoke(sp, (Object) new String[] {
                    "SECP384R1MLKEM1024"
                });
                server.setSSLParameters(sp);

                /* Client offers only classical groups. */
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);
                SSLParameters cp = client.getSSLParameters();
                setM.invoke(cp, (Object) new String[] { "secp256r1" });
                client.setSSLParameters(cp);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertFalse("Handshake must fail: server restricts to PQC, " +
                    "client offers classical only", ret == 0);
            }
            finally {
                if (prev == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prev);
                }
            }
        }
    }

    /**
     * With no SSLEngine override and no Security property set, the helper
     * must report null.
     */
    @Test
    public void testHelper_unsetReturnsNull() {

        SSLParameters p = new SSLParameters();
        String[] result = WolfSSLParametersHelper.getNamedGroupsFromParams(p);
        assertNull("Unset SSLParameters.namedGroups must surface as null",
            result);
    }

    /**
     * getNamedGroupsFromParams must tolerate a null input without throwing.
     */
    @Test
    public void testHelper_nullInputReturnsNull() {

        assertNull(WolfSSLParametersHelper.getNamedGroupsFromParams(null));
    }

    /**
     * jdk.tls.namedGroups System property alone (no wolfJSSE Security prop or
     * SSLEngine override) must do a successful PQC handshake.
     */
    @Test
    public void testJdkTlsNamedGroupsAloneDrivesHandshake() throws Exception {

        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (curvesPropLock) {
            String prevWolf = Security.getProperty(CURVES_PROP);
            String prevJdk = System.getProperty(JDK_GROUPS_PROP);
            try {
                Security.setProperty(CURVES_PROP, "");
                System.setProperty(JDK_GROUPS_PROP, "SECP256R1MLKEM768");

                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("jdk.tls.namedGroups alone should drive a " +
                    "successful PQC handshake", 0, ret);
            }
            finally {
                if (prevWolf == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prevWolf);
                }
                if (prevJdk == null) {
                    System.clearProperty(JDK_GROUPS_PROP);
                }
                else {
                    System.setProperty(JDK_GROUPS_PROP, prevJdk);
                }
            }
        }
    }

    /**
     * Both static properties set. Each is read by its own helper and applied
     * via separate native useSupportedCurves call. The two lists accumulate in
     * native wolfSSL's supported_groups extension.
     *
     * Verifies that each property is read independently (no cross
     * contamination), and successful handshake negotiates supported groups.
     */
    @Test
    public void testStaticPropertiesIndependentlyApplied() throws Exception {

        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (curvesPropLock) {
            String prevWolf = Security.getProperty(CURVES_PROP);
            String prevJdk = System.getProperty(JDK_GROUPS_PROP);
            try {
                /* wolfJSSE property has only the legacy hybrid (server won't
                 * accept this if alone); jdk.tls.namedGroups has the working
                 * IETF hybrid. Both should be applied. The handshake must
                 * succeed because the IETF hybrid is in the union. */
                Security.setProperty(CURVES_PROP, "secp256r1");
                System.setProperty(JDK_GROUPS_PROP, "SECP256R1MLKEM768");

                /* Each helper returns only its own property's contents. */
                Method getSC = com.wolfssl.provider.jsse.WolfSSLUtil.class
                    .getDeclaredMethod("getSupportedCurves");
                getSC.setAccessible(true);
                String[] sc = (String[]) getSC.invoke(null);
                assertArrayEquals(
                    "getSupportedCurves must read only wolfJSSE property",
                    new String[] { "secp256r1" }, sc);

                Method getJdk = com.wolfssl.provider.jsse.WolfSSLUtil.class
                    .getDeclaredMethod("getJdkTlsNamedGroups");
                getJdk.setAccessible(true);
                String[] jdk = (String[]) getJdk.invoke(null);
                assertArrayEquals(
                    "getJdkTlsNamedGroups must read only JDK property",
                    new String[] { "SECP256R1MLKEM768" }, jdk);

                /* End-to-end: both apply, native union enables both groups,
                 * handshake picks one. */
                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Both static properties together should " +
                    "drive a successful handshake", 0, ret);
            }
            finally {
                if (prevWolf == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prevWolf);
                }
                if (prevJdk == null) {
                    System.clearProperty(JDK_GROUPS_PROP);
                }
                else {
                    System.setProperty(JDK_GROUPS_PROP, prevJdk);
                }
            }
        }
    }

    /**
     * SSLEngine setNamedGroups must override jdk.tls.namedGroups, like it
     * overrides the wolfJSSE Security property. Sets a wrong group
     * jdk.tls.namedGroups, then SSLEngine overrides with the right one, and
     * the handshake must succeed.
     */
    @Test
    public void testPerEngineOverridesJdkProperty() throws Exception {

        Assume.assumeTrue("Host JDK lacks SSLParameters.setNamedGroups",
            jdkHasNamedGroups);
        Assume.assumeTrue("ML-KEM not enabled in native wolfSSL",
            WolfSSL.MLKEMEnabled() && WolfSSL.TLSv13Enabled());

        synchronized (curvesPropLock) {
            String prevWolf = Security.getProperty(CURVES_PROP);
            String prevJdk = System.getProperty(JDK_GROUPS_PROP);

            try {
                Security.setProperty(CURVES_PROP, "");
                System.setProperty(JDK_GROUPS_PROP, "secp256r1");

                SSLContext ctx = tf.createSSLContext("TLSv1.3", PROVIDER);
                SSLEngine server = ctx.createSSLEngine();
                server.setUseClientMode(false);
                server.setNeedClientAuth(false);
                SSLEngine client =
                    ctx.createSSLEngine("wolfSSL named groups test", 11111);
                client.setUseClientMode(true);

                Method setM = SSLParameters.class.getMethod(
                    "setNamedGroups", String[].class);
                String[] perEngine = new String[] { "SECP256R1MLKEM768" };

                SSLParameters cp = client.getSSLParameters();
                setM.invoke(cp, (Object) perEngine);
                client.setSSLParameters(cp);

                SSLParameters sp = server.getSSLParameters();
                setM.invoke(sp, (Object) perEngine);
                server.setSSLParameters(sp);

                int ret = tf.testConnection(server, client, null,
                    new String[] { "TLSv1.3" }, APP_DATA);
                assertEquals("Per-engine setNamedGroups must override " +
                    "jdk.tls.namedGroups", 0, ret);
            }
            finally {
                if (prevWolf == null) {
                    Security.setProperty(CURVES_PROP, "");
                }
                else {
                    Security.setProperty(CURVES_PROP, prevWolf);
                }
                if (prevJdk == null) {
                    System.clearProperty(JDK_GROUPS_PROP);
                }
                else {
                    System.setProperty(JDK_GROUPS_PROP, prevJdk);
                }
            }
        }
    }
}

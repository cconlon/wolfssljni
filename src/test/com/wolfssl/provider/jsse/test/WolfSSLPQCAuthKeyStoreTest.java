/* WolfSSLPQCAuthKeyStoreTest.java
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
import com.wolfssl.provider.jsse.WolfSSLProvider;
import com.wolfssl.test.TimedTestWatcher;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import static org.junit.Assert.assertEquals;

/**
 * ML-DSA cert authentication tests via standard JCE KeyStore. Covers both
 * JKS and PKCS12 store types. PKCS12 is the JDK 24+ default keystore type,
 * JKS is included for backward-compatibility coverage.
 *
 * Exercises the standard Java security stack that a typical JDK 24+ app
 * would use:
 *   - KeyStore.getInstance() to load an ML-DSA private key + cert chain
 *   - KeyManagerFactory / TrustManagerFactory through wolfJSSE
 *   - Standard SSLContext.init()
 *
 * Skipped on JDK less than 24: ML-DSA KeyFactory was added in JEP 497 (JDK 24).
 * Older JDKs cannot load ML-DSA private keys from a standard keystore, but the
 * keystore files themselves are only opened when this test runs.
 *
 * The test fixtures (server-mldsa{44,65,87}.{jks,p12} and
 * ca-mldsa{44,65,87}.{jks,p12} under examples/provider/) are produced by
 * examples/provider/update-keystore-pqc.sh, which requires JDK 24+.
 *
 * For coverage on older JDKs (or when not relying on a JCE keystore at all),
 * see {@link WolfSSLPQCAuthenticationTest}, which loads PEM keys through a
 * custom KeyManager.
 */
public class WolfSSLPQCAuthKeyStoreTest {

    private static final String PROVIDER = "wolfJSSE";
    private static final String APP_DATA = "PQC keystore test";
    private static final char[] STORE_PASS = "wolfSSL test".toCharArray();

    private static WolfSSLTestFactory tf;
    private static boolean jdkHasMlDsa = false;

    @Rule
    public TestRule testWatcher = TimedTestWatcher.create();

    @BeforeClass
    public static void setUp() throws Exception {

        System.out.println("WolfSSLPQCAuthKeyStore Class");

        Security.insertProviderAt(new WolfSSLProvider(), 1);
        tf = new WolfSSLTestFactory();

        /* Probe for ML-DSA KeyFactory (JEP 497, JDK 24+). Cached for lifetime
         * of the test class so all @Test methods can do a cheap check. */
        try {
            KeyFactory.getInstance("ML-DSA");
            jdkHasMlDsa = true;
        } catch (NoSuchAlgorithmException e) {
            jdkHasMlDsa = false;
        }
    }

    /**
     * Shared per-test precondition check. Routes through Assume so the
     * TimedTestWatcher reports SKIP rather than the test failing.
     */
    private void preconditions(String storeFilename) {

        Assume.assumeTrue(WolfSSL.MLDSAEnabled() && WolfSSL.TLSv13Enabled());

        Assume.assumeTrue("JDK < 24, no JCE ML-DSA KeyFactory", jdkHasMlDsa);

        Assume.assumeTrue("Keystore missing; run examples/provider/" +
            "update-keystore-pqc.sh first",
            new File("examples/provider/" + storeFilename).isFile());

        Assume.assumeTrue(WolfSSLPQCTestUtil.MLDSA_CERT_PARSING_SKIP_MSG,
            WolfSSLPQCTestUtil.nativeMlDsaCertParsingSupported());
    }

    /**
     * Do a TLS 1.3 ML-DSA-N handshake using the given store type and file
     * extension. Both server keystore and client truststore use the same
     * format, mirroring how an app typically picks one keystore convention.
     *
     * @param level     ML-DSA parameter set: 44, 65, or 87
     * @param storeType JCE KeyStore type: "JKS" or "PKCS12"
     * @param ext       file extension matching storeType: "jks" or "p12"
     */
    private void runHandshake(int level, String storeType, String ext)
        throws Exception {

        String serverPath =
            "examples/provider/server-mldsa" + level + "." + ext;
        String caPath = "examples/provider/ca-mldsa" + level + "." + ext;

        /* Server keystore: private key + CA-signed cert chain. */
        KeyStore serverKs = KeyStore.getInstance(storeType);
        FileInputStream in = new FileInputStream(serverPath);
        try {
            serverKs.load(in, STORE_PASS);
        } finally {
            in.close();
        }
        KeyManagerFactory kmf =
            KeyManagerFactory.getInstance("SunX509", PROVIDER);
        kmf.init(serverKs, STORE_PASS);

        /* Client truststore: just the root CA cert (no private key). */
        KeyStore caKs = KeyStore.getInstance(storeType);
        in = new FileInputStream(caPath);
        try {
            caKs.load(in, STORE_PASS);
        } finally {
            in.close();
        }
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance("SunX509", PROVIDER);
        tmf.init(caKs);

        SSLContext serverCtx = tf.createSSLContext("TLSv1.3", PROVIDER,
            null, kmf.getKeyManagers());
        SSLContext clientCtx = tf.createSSLContext("TLSv1.3", PROVIDER,
            tmf.getTrustManagers(), null);

        SSLEngine server = serverCtx.createSSLEngine();
        server.setUseClientMode(false);
        server.setNeedClientAuth(false);

        SSLEngine client = clientCtx.createSSLEngine(
            "wolfSSL " + storeType + " PQC test", 11111);
        client.setUseClientMode(true);

        int ret = tf.testConnection(server, client, null,
            new String[] { "TLSv1.3" }, APP_DATA);
        assertEquals("ML-DSA-" + level + " " + storeType +
            " handshake should succeed", 0, ret);
    }

    /* JKS coverage. */
    @Test
    public void testJksServerAuth_MLDSA44() throws Exception {
        preconditions("server-mldsa44.jks");
        runHandshake(44, "JKS", "jks");
    }

    @Test
    public void testJksServerAuth_MLDSA65() throws Exception {
        preconditions("server-mldsa65.jks");
        runHandshake(65, "JKS", "jks");
    }

    @Test
    public void testJksServerAuth_MLDSA87() throws Exception {
        preconditions("server-mldsa87.jks");
        runHandshake(87, "JKS", "jks");
    }

    /* PKCS12 coverage (JDK 24+ default keystore type). */
    @Test
    public void testPkcs12ServerAuth_MLDSA44() throws Exception {
        preconditions("server-mldsa44.p12");
        runHandshake(44, "PKCS12", "p12");
    }

    @Test
    public void testPkcs12ServerAuth_MLDSA65() throws Exception {
        preconditions("server-mldsa65.p12");
        runHandshake(65, "PKCS12", "p12");
    }

    @Test
    public void testPkcs12ServerAuth_MLDSA87() throws Exception {
        preconditions("server-mldsa87.p12");
        runHandshake(87, "PKCS12", "p12");
    }
}

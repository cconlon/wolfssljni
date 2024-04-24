/* WolfSSLSessionTest.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

package com.wolfssl.test;

import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import static org.junit.Assert.*;

import java.net.Socket;
import java.net.UnknownHostException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLPskClientCallback;
import com.wolfssl.WolfSSLPskServerCallback;
import com.wolfssl.WolfSSLTls13SecretCallback;
import com.wolfssl.WolfSSLSession;

public class WolfSSLSessionTest {

    private final static int TEST_FAIL    = -1;
    private final static int TEST_SUCCESS =  0;

    private static String cliCert = "./examples/certs/client-cert.pem";
    private static String cliKey  = "./examples/certs/client-key.pem";
    private static String caCert  = "./examples/certs/ca-cert.pem";
    private static String bogusFile = "/dev/null";

    private final static String exampleHost = "www.example.com";
    private final static int examplePort = 443;

    private static WolfSSLContext ctx = null;

    @BeforeClass
    public static void loadLibrary()
        throws WolfSSLException{

        System.out.println("WolfSSLSession Class");

        try {
            WolfSSL.loadLibrary();
        } catch (UnsatisfiedLinkError ule) {
            fail("failed to load native JNI library");
        }

        /* Create one WolfSSLContext */
        ctx = new WolfSSLContext(WolfSSL.SSLv23_ClientMethod());

        /* Set cert/key paths */
        cliCert = WolfSSLTestCommon.getPath(cliCert);
        cliKey = WolfSSLTestCommon.getPath(cliKey);
        caCert = WolfSSLTestCommon.getPath(caCert);
    }

    @Test
    public void test_WolfSSLSession_new()
        throws WolfSSLJNIException {

        WolfSSLSession sess = null;

        System.out.print("\tWolfSSLSession()");

        try {
            sess = new WolfSSLSession(ctx);

        } catch (WolfSSLException we) {
            System.out.println("\t... failed");
            fail("failed to create WolfSSLSession object");

        } finally {
            if (sess != null) {
                sess.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useCertificateFile()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tuseCertificateFile()");

        WolfSSLSession ssl = new WolfSSLSession(ctx);

        test_ucf("useCertificateFile", null, null, 9999, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(null, null, 9999)");

        test_ucf("useCertificateFile", ssl, bogusFile,
                 WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ssl, bogusFile, SSL_FILETYPE_PEM)");

        test_ucf("useCertificateFile", ssl, cliCert, 9999,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateFile(ssl, cliCert, 9999)");

        test_ucf("useCertificateFile", ssl, cliCert,
                 WolfSSL.SSL_FILETYPE_PEM,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateFile(ssl, cliCert, SSL_FILETYPE_PEM)");

        if (ssl != null) {
            ssl.freeSSL();
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useCertificateChainFile()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tuseCertificateChainFile()");

        WolfSSLSession ssl = new WolfSSLSession(ctx);

        test_ucf("useCertificateChainFile", null, null, 0,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateChainFile(null, null)");

        test_ucf("useCertificateChainFile", ssl, bogusFile, 0,
                 WolfSSL.SSL_FAILURE,
                 "useCertificateChainFile(ssl, bogusFile)");

        test_ucf("useCertificateChainFile", ssl, cliCert, 0,
                 WolfSSL.SSL_SUCCESS,
                 "useCertificateChainFile(ssl, cliCert)");

        if (ssl != null) {
            ssl.freeSSL();
        }

        System.out.println("\t... passed");
    }

    /* helper for testing WolfSSLSession.useCertificateFile() */
    private void test_ucf(String func, WolfSSLSession ssl, String filePath,
        int type, int cond, String name) {

        int result = WolfSSL.SSL_FAILURE;

        try {

            if (func.equals("useCertificateFile")) {
                result = ssl.useCertificateFile(filePath, type);
            } else if (func.equals("useCertificateChainFile")) {
                result = ssl.useCertificateChainFile(filePath);
            } else {
                fail(name + " failed");
            }

            if ((result != cond) && (result != WolfSSL.NOT_COMPILED_IN))
            {
                if (func.equals("useCertificateFile")) {
                    System.out.println("\t\t... failed");
                } else {
                    System.out.println("\t... failed");
                }
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (ssl == null) {
                return;
            }
        }

        return;
    }

    @Test
    public void test_WolfSSLSession_usePrivateKeyFile()
        throws WolfSSLJNIException, WolfSSLException {

        System.out.print("\tusePrivateKeyFile()");

        WolfSSLSession ssl = new WolfSSLSession(ctx);

        test_upkf(null, null, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(null, null, 9999)");

        test_upkf(ssl, bogusFile, WolfSSL.SSL_FILETYPE_PEM,
                  WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ssl, bogusFile, SSL_FILETYPE_PEM)");

        test_upkf(ssl, cliKey, 9999, WolfSSL.SSL_FAILURE,
                 "usePrivateKeyFile(ssl, cliKey, 9999)");

        test_upkf(ssl, cliKey, WolfSSL.SSL_FILETYPE_PEM, WolfSSL.SSL_SUCCESS,
                 "usePrivateKeyFile(ssl, cliKey, SSL_FILETYPE_PEM)");

        if (ssl != null) {
            ssl.freeSSL();
        }

        System.out.println("\t\t... passed");
    }

    /* helper for testing WolfSSLSession.usePrivateKeyFile() */
    private void test_upkf(WolfSSLSession ssl, String filePath, int type,
        int cond, String name) {

        int result;

        try {

            result = ssl.usePrivateKeyFile(filePath, type);
            if ((result != cond) && (result != WolfSSL.NOT_COMPILED_IN))
            {
                System.out.println("\t\t... failed");
                fail(name + " failed");
            }

        } catch (NullPointerException e) {

            /* correctly handle NULL pointer */
            if (ssl == null) {
                return;
            }
        }

        return;
    }

    class TestPskClientCb implements WolfSSLPskClientCallback
    {
        public long pskClientCallback(WolfSSLSession ssl, String hint,
                StringBuffer identity, long idMaxLen, byte[] key,
                long keyMaxLen) {

            /* set the client identity */
            if (identity.length() != 0)
                return 0;
            identity.append("Client_identity");

            /* set the client key, max key size is key.length */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            /* return size of key */
            return 4;
        }
    }

    @Test
    public void test_WolfSSLSession_setPskClientCb()
        throws WolfSSLJNIException {

        WolfSSLSession ssl = null;

        System.out.print("\tsetPskClientCb()");

        try {
            TestPskClientCb pskClientCb = new TestPskClientCb();
            ssl = new WolfSSLSession(ctx);
            ssl.setPskClientCb(pskClientCb);

        } catch (Exception e) {
            if (e.getMessage().equals("wolfSSL not compiled with PSK " +
                "support")) {
                /* Not compiled in, skip */
                System.out.println("\t\t... skipped");
                return;
            }
            else {
                System.out.println("\t\t... failed");
                fail("Failed setPskClientCb test");
                e.printStackTrace();
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    class TestPskServerCb implements WolfSSLPskServerCallback
    {
        public long pskServerCallback(WolfSSLSession ssl, String identity,
                byte[] key, long keyMaxLen) {

            /* check the client identity */
            if (!identity.equals("Client_identity"))
                return 0;

            /* set the server key, max key size is key.length */
            key[0] = 26;
            key[1] = 43;
            key[2] = 60;
            key[3] = 77;

            /* return size of key */
            return 4;
        }
    }

    @Test
    public void test_WolfSSLSession_setPskServerCb()
        throws WolfSSLJNIException {

        WolfSSLSession ssl = null;

        System.out.print("\tsetPskServerCb()");

        try {
            TestPskServerCb pskServerCb = new TestPskServerCb();
            ssl = new WolfSSLSession(ctx);
            ssl.setPskServerCb(pskServerCb);

        } catch (Exception e) {
            if (e.getMessage().equals("wolfSSL not compiled with PSK " +
                "support")) {
                /* Not compiled in, skip */
                System.out.println("\t\t... skipped");
                return;
            }
            else {
                System.out.println("\t\t... failed");
                fail("Failed setPskServerCb test");
                e.printStackTrace();
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useGetPskIdentityHint()
        throws WolfSSLJNIException, WolfSSLException {

        int ret = 0;
        String hint = null;
        WolfSSLSession ssl = null;

        System.out.print("\tuse/getPskIdentityHint()");

        ssl = new WolfSSLSession(ctx);

        try {
            /* Set PSK identity hint */
            ret = ssl.usePskIdentityHint("wolfssl hint");
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t... failed");
                fail("usePskIdentityHint failed");
            }

            /* Get PSK identity hint */
            hint = ssl.getPskIdentityHint();
            if (hint != null && !hint.equals("wolfssl hint")) {
                System.out.println("\t... failed");
                fail("getPskIdentityHint failed");
            }

        } catch (IllegalStateException e) {
            System.out.println("\t... failed");
            e.printStackTrace();
            fail("Failed use/getPskIdentityHint test");

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useSessionTicket()
        throws WolfSSLJNIException, WolfSSLException {

        int ret = 0;
        WolfSSLSession ssl = null;

        System.out.print("\tuseSessionTicket()");

        try {
            ssl = new WolfSSLSession(ctx);

            ret = ssl.useSessionTicket();
            if (ret != WolfSSL.SSL_SUCCESS &&
                ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t... failed");
                fail("useSessionTicket failed");
            }

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            e.printStackTrace();

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_getPskIdentity()
        throws WolfSSLJNIException, WolfSSLException {

        String identity = null;
        WolfSSLSession ssl = null;

        System.out.print("\tgetPskIdentity()");

        try {
            ssl = new WolfSSLSession(ctx);
            identity = ssl.getPskIdentity();

        } catch (IllegalStateException e) {
            System.out.println("\t\t... failed");
            fail("Failed getPskIdentity test");
            e.printStackTrace();

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_timeout()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\ttimeout()");

        ssl = new WolfSSLSession(ctx);

        try {
            ssl.setTimeout(5);
            if (ssl.getTimeout() != 5) {
                System.out.println("\t\t\t... failed");
                fail("Failed timeout test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_status()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\tstatus()");

        ssl = new WolfSSLSession(ctx);

        try {
            if (ssl.handshakeDone() == true) {
                System.out.println("\t\t\t... failed");
                fail("Failed status test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useSNI()
        throws WolfSSLJNIException, WolfSSLException {

        int ret;
        String sniHostName = "www.example.com";
        WolfSSLSession ssl = null;

        System.out.print("\tuseSNI()");

        ssl = new WolfSSLSession(ctx);

        try {
            ret = ssl.useSNI((byte)0, sniHostName.getBytes());
            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t\t... skipped");
                return;
            } else if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t\t... failed");
                fail("Failed useSNI test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useALPN()
        throws WolfSSLException, WolfSSLJNIException {

        int ret;
        String[] alpnProtos = new String[] {
            "h2", "http/1.1"
        };
        String http11Alpn = "http/1.1";
        byte[] alpnProtoBytes = http11Alpn.getBytes();
        byte[] alpnProtoBytesPacked = new byte[1 + alpnProtoBytes.length];
        WolfSSLSession ssl = null;

        System.out.print("\tuseALPN()");

        ssl = new WolfSSLSession(ctx);

        try {
            /* Testing useALPN(String[], int) */
            ret = ssl.useALPN(alpnProtos,
                WolfSSL.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(alpnProtos,
                    WolfSSL.WOLFSSL_ALPN_FAILED_ON_MISMATCH);
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(null,
                    WolfSSL.WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
                if (ret < 0) {
                    /* error expected, null input */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(alpnProtos, 0);
                if (ret < 0) {
                    /* error expected, no options */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(alpnProtos, -123);
                if (ret < 0) {
                    /* error expected, invalid options */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            /* Testing useALPN(byte[]) */
            if (ret == WolfSSL.SSL_SUCCESS) {

                alpnProtoBytesPacked[0] = (byte)http11Alpn.length();
                System.arraycopy(alpnProtoBytes, 0, alpnProtoBytesPacked, 1,
                    alpnProtoBytes.length);

                ret = ssl.useALPN(alpnProtoBytesPacked);
            }

            if (ret == WolfSSL.SSL_SUCCESS) {
                ret = ssl.useALPN(null);
                if (ret < 0) {
                    /* error expected, null input */
                    ret = WolfSSL.SSL_SUCCESS;
                }
            }

            if (ret == WolfSSL.NOT_COMPILED_IN) {
                System.out.println("\t\t\t... skipped");
                return;

            } else if (ret != WolfSSL.SSL_SUCCESS) {
                System.out.println("\t\t\t... failed");
                fail("Failed useALPN test");
            }

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_freeSSL()
        throws WolfSSLJNIException, WolfSSLException {

        WolfSSLSession ssl = null;

        System.out.print("\tfreeSSL()");

        ssl = new WolfSSLSession(ctx);

        try {
            ssl.freeSSL();

        } catch (WolfSSLJNIException e) {
            System.out.println("\t\t\t... failed");
            fail("Failed freeSSL test");
            e.printStackTrace();

        }

        System.out.println("\t\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_UseAfterFree()
        throws WolfSSLJNIException {

        int ret, err;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;

        System.out.print("\tTesting use after free");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            sock = new Socket(exampleHost, examplePort);
            ret = ssl.setFd(sock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                ssl.freeSSL();
                sslCtx.free();
                fail("Failed to set file descriptor");
            }

            /* successful connection test */
            do {
                ret = ssl.connect();
                err = ssl.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("Failed WolfSSL.connect() to " + exampleHost);
            }

        } catch (UnknownHostException | ConnectException e) {
            /* skip if no Internet connection */
            System.out.println("\t\t... skipped");
            return;

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            fail("Failed UseAfterFree test");
            e.printStackTrace();
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        try {
            /* this should fail, use after free */
            ret = ssl.connect();

        } catch (IllegalStateException ise) {
            System.out.println("\t\t... passed");
            return;

        } catch (SocketTimeoutException | SocketException e) {
            System.out.println("\t\t... failed");
            fail("Failed UseAfterFree test");
            e.printStackTrace();
            return;
        }

        /* fail here means WolfSSLSession was used after free without
         * exception thrown */
        System.out.println("\t\t... failed");
        fail("WolfSSLSession was able to be used after freed");
    }

    @Test
    public void test_WolfSSLSession_getSessionID()
        throws WolfSSLJNIException {

        int ret, err;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;
        byte[] sessionID = null;

        System.out.print("\tTesting getSessionID()");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            sessionID = ssl.getSessionID();
            if (sessionID == null || sessionID.length != 0) {
                /* sessionID array should not be null, but should be empty */
                fail("Session ID should be empty array before connection");
            }

            sock = new Socket(exampleHost, examplePort);
            ret = ssl.setFd(sock);
            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("Failed to set file descriptor");
            }

            /* successful connection test */
            do {
                ret = ssl.connect();
                err = ssl.getError(ret);
            } while (ret != WolfSSL.SSL_SUCCESS &&
                   (err == WolfSSL.SSL_ERROR_WANT_READ ||
                    err == WolfSSL.SSL_ERROR_WANT_WRITE));

            if (ret != WolfSSL.SSL_SUCCESS) {
                fail("Failed WolfSSL.connect() to " + exampleHost);
            }

            sessionID = ssl.getSessionID();
            if (sessionID == null || sessionID.length == 0) {
                /* session ID should not be null or zero length */
                fail("Session ID should not be null or 0 length " +
                     "after connection");
            }

        } catch (UnknownHostException | ConnectException e) {
            /* skip if no Internet connection */
            System.out.println("\t\t... skipped");
            return;

        } catch (Exception e) {
            System.out.println("\t\t... failed");
            fail("Failed getSessionID test");
            e.printStackTrace();
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        System.out.println("\t\t... passed");
    }

    @Test
    public void test_WolfSSLSession_useSecureRenegotiation()
        throws WolfSSLJNIException {

        int ret, err;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        Socket sock = null;
        byte[] sessionID = null;

        System.out.print("\tTesting useSecureRenegotiation()");

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_2_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            /* test if enable call succeeds */
            ret = ssl.useSecureRenegotiation();
            if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
                System.out.println("... failed");
                fail("Failed useSecureRenegotiation test");
                return;
            }

        } catch (Exception e) {
            System.out.println("... failed");
            fail("Failed useSecureRenegotiation test");
            e.printStackTrace();
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        System.out.println("... passed");
    }

    class TestTls13SecretCb implements WolfSSLTls13SecretCallback
    {
        public int tls13SecretCallback(WolfSSLSession ssl, int id,
            byte[] secret, Object ctx)
        {
            return 0;
        }
    }

    @Test
    public void test_WolfSSLSession_setTls13SecretCb()
        throws WolfSSLJNIException {

        int ret;
        WolfSSL sslLib = null;
        WolfSSLContext sslCtx = null;
        WolfSSLSession ssl = null;
        TestTls13SecretCb cb = null;

        System.out.print("\tTesting setTls13SecretCb()");

        if (!WolfSSL.secretCallbackEnabled()) {
            System.out.println("\t... skipped");
            return;
        }

        try {

            /* setup library, context, session, socket */
            sslLib = new WolfSSL();
            sslCtx = new WolfSSLContext(WolfSSL.TLSv1_3_ClientMethod());
            sslCtx.setVerify(WolfSSL.SSL_VERIFY_NONE, null);
            ssl = new WolfSSLSession(sslCtx);

            /* setting with null should pass */
            ssl.setTls13SecretCb(null, null);

            /* set with test callback */
            cb = new TestTls13SecretCb();
            ssl.setTls13SecretCb(cb, null);

        } catch (Exception e) {
            System.out.println("\t... failed");
            e.printStackTrace();
            fail("failed setTls13SecretCb() test");
            return;

        } finally {
            if (ssl != null) {
                ssl.freeSSL();
            }
            if (sslCtx != null) {
                sslCtx.free();
            }
        }

        System.out.println("\t... passed");
    }
}


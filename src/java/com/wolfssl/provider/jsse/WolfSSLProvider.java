/* WolfSSLProvider.java
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.provider.jsse;

import java.security.Provider;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLFIPSErrorCallback;

/**
 * wolfSSL JSSE Provider implementation
 *
 * @author wolfSSL
 * @version 1.0
 */
public final class WolfSSLProvider extends Provider {

    /* Keep one static reference to native wolfSSL library across
     * all WolfSSLProvider objects. */
    private static WolfSSL sslLib = null;

    public class JSSEFIPSErrorCallback implements WolfSSLFIPSErrorCallback {
        public void errorCallback(int ok, int err, String hash) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "In FIPS error callback, ok = " + ok + " err = " + err);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "hash = " + hash);

            if (err == -203) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                 "In core integrity hash check failure, copy above hash");
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                 "into verifyCore[] in fips_test.c and rebuild native wolfSSL");
            }
        }
    }

    public WolfSSLProvider() {
        super("wolfJSSE", 1, "wolfSSL JSSE Provider");
        //super("wolfJSSE", "1.0", "wolfSSL JSSE Provider");

        /* load native wolfSSLJNI library */
        WolfSSL.loadLibrary();

        /* Register wolfCrypt FIPS error callback. Used for FIPS builds to
         * output correct verifyCore hash to logging mechanism. */
        int rc = WolfSSL.setFIPSCb(new JSSEFIPSErrorCallback());
        if (rc != WolfSSL.SSL_SUCCESS) {
            if (rc == WolfSSL.NOT_COMPILED_IN) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "FIPS callback not set, not using wolfCrypt FIPS");
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Error setting wolfCrypt FIPS Callback, ret = " + rc);
            }
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Registered wolfCrypt FIPS error callback");
        }

        try {
            /* initialize native wolfSSL */
            sslLib = new WolfSSL();
        } catch (WolfSSLException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Failed to initialize native wolfSSL library");
        }

        /* enable native wolfSSL debug logging, native wolfSSL must be
         * compiled with --enable-debug */
        String wolfsslDebug = System.getProperty("wolfssl.debug");
        if ((wolfsslDebug != null) && (wolfsslDebug.equalsIgnoreCase("true"))) {
            WolfSSL.debuggingON();
        }

        /* Key Factory */
        put("KeyManagerFactory.X509",
                "com.wolfssl.provider.jsse.WolfSSLKeyManager");
        put("KeyManagerFactory.SunX509",
                "com.wolfssl.provider.jsse.WolfSSLKeyManager");

        /* TLS connection Contexts */
        if (WolfSSL.TLSv1Enabled()) {
            put("SSLContext.TLSv1",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV1_Context");
        }
        if (WolfSSL.TLSv11Enabled()) {
            put("SSLContext.TLSv1.1",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV11_Context");
        }
        if (WolfSSL.TLSv12Enabled()) {
            put("SSLContext.TLSv1.2",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV12_Context");
        }
        if (WolfSSL.TLSv13Enabled()) {
            put("SSLContext.TLSv1.3",
                    "com.wolfssl.provider.jsse.WolfSSLContext$TLSV13_Context");
        }
        put("SSLContext.SSL",
                "com.wolfssl.provider.jsse.WolfSSLContext$TLSV23_Context");
        put("SSLContext.TLS",
                "com.wolfssl.provider.jsse.WolfSSLContext$TLSV23_Context");
        put("SSLContext.DEFAULT",
                "com.wolfssl.provider.jsse.WolfSSLContext$DEFAULT_Context");

        /* Trust Factory */
        put("TrustManagerFactory.PKIX",
                "com.wolfssl.provider.jsse.WolfSSLTrustManager");
        put("TrustManagerFactory.X509",
                "com.wolfssl.provider.jsse.WolfSSLTrustManager");
        put("TrustManagerFactory.SunX509",
                "com.wolfssl.provider.jsse.WolfSSLTrustManager");

        /* Key Stores */
        put("KeyStore.PKCS12",
                "com.wolfssl.provider.jsse.WolfSSLPKCS12KeyStore");
    }
}


/* WolfSSL.java
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

package com.wolfssl;

/**
 * Base class which wraps the native WolfSSL embedded SSL library.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * @author  wolfSSL
 */
public class WolfSSL {

    /* If this enum is changed, also change switch statement cases in
     * ./native/com_wolfssl_WolfSSL.c,
     * Java_com_wolfssl_WolfSSL_getAvailableCipherSuitesIana() */
    /** TLS protocol versions */
    public enum TLS_VERSION {
        /** invalid TLS version */
        INVALID,
        /** TLS 1.0 */
        TLSv1,
        /** TLS 1.1 */
        TLSv1_1,
        /** TLS 1.2 */
        TLSv1_2,
        /** TLS 1.3 */
        TLSv1_3,
        /** Downgrade starting from highest supported SSL/TLS version */
        SSLv23
    }

    /* ------------------ wolfSSL JNI error codes ----------------------- */
    /** Session unavailable */
    public static final int JNI_SESSION_UNAVAILABLE = -10001;

    /**
     * Socket timed out, matches com_wolfssl_WolfSSLSession.c socketSelect()
     * return value */
    public static final int WOLFJNI_TIMEOUT = -11;

    /* ----------------------- wolfSSL codes ---------------------------- */

    /** Error code: no error */
    public static final int SSL_ERROR_NONE      =  0;
    /** Error code: failure */
    public static final int SSL_FAILURE         =  0;
    /** Error code: success */
    public static final int SSL_SUCCESS         =  1;
    /** Error code: TLS shutdown not done */
    public static final int SSL_SHUTDOWN_NOT_DONE = 2;

    /** Error code: bad certificate */
    public static final int SSL_BAD_CERTTYPE    = -8;
    /** Error code: bad file stat */
    public static final int SSL_BAD_STAT        = -7;
    /** Error code: bad path */
    public static final int SSL_BAD_PATH        = -6;
    /** Error code: bad file type */
    public static final int SSL_BAD_FILETYPE    = -5;
    /** Error code: bad file */
    public static final int SSL_BAD_FILE        = -4;
    /** Error code: not implemented */
    public static final int SSL_NOT_IMPLEMENTED = -3;
    /** Error code: unknown */
    public static final int SSL_UNKNOWN         = -2;
    /** Error code: fatal error */
    public static final int SSL_FATAL_ERROR     = -1;

    /** wolfSSL file type: ASN.1/DER */
    public static final int SSL_FILETYPE_ASN1    = 2;
    /** wolfSSL file type: PEM */
    public static final int SSL_FILETYPE_PEM     = 1;
    /** ASN1 */
    public static final int SSL_FILETYPE_DEFAULT = 2;
    /** NTRU raw key blog */
    public static final int SSL_FILETYPE_RAW     = 3;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> the client will not verify the certificate
     * received from the server and the handshake will continue as normal.
     * <br>
     * <b>Server mode:</b> the server will not send a certificate request
     * to the client. As such, client verification will not be enabled.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_NONE = 0;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> the client will verify the certificate received
     * from the server during the handshake. This is turned on by default
     * in wolfSSL, therefore, using this option has no effect.
     * <br>
     * <b>Server mode:</b> the server will send a certificate request to the
     * client and verify the client certificate which is received.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_PEER = 1;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> no effect when used on the client side.
     * <br>
     * <b>Server mode:</b> the verification will fail on the server side
     * if the client fails to send a certificate when requested to do so
     * (when using SSL_VERIFY_PEER on the SSL server).
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;

    /**
     * Verification mode for peer certificates.
     * Currently not supported by native wolfSSL.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_CLIENT_ONCE          = 4;

    /** Disable session cache */
    public static final int SSL_SESS_CACHE_OFF                = 30;
    /** currently unused */
    public static final int SSL_SESS_CACHE_CLIENT             = 31;
    /** Native session cache mode: server */
    public static final int SSL_SESS_CACHE_SERVER             = 32;
    /** currently unused */
    public static final int SSL_SESS_CACHE_BOTH               = 33;
    /** Native session cache mode: auto flush */
    public static final int SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34;
    /** currently unused */
    public static final int SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35;

    /** I/O read would block, wolfSSL needs more data */
    public static final int SSL_ERROR_WANT_READ        =  2;
    /** I/O send would block, wolfSSL needs to write data */
    public static final int SSL_ERROR_WANT_WRITE       =  3;
    /** currently unused */
    public static final int SSL_ERROR_WANT_CONNECT     =  7;
    /** currently unused */
    public static final int SSL_ERROR_WANT_ACCEPT      =  8;
    /** Error with underlying I/O */
    public static final int SSL_ERROR_SYSCALL          =  5;
    /** I/O operation should be called again when client cert is available */
    public static final int SSL_ERROR_WANT_X509_LOOKUP = 83;
    /** I/O error, zero return, no more data */
    public static final int SSL_ERROR_ZERO_RETURN      =  6;
    /** Generatl SSL error */
    public static final int SSL_ERROR_SSL              = 85;
    /** Peer closed socket */
    public static final int SSL_ERROR_SOCKET_PEER_CLOSED = -397;

    /* extra definitions from ssl.h */
    /** CertManager: check all cert CRLs */
    public static final int WOLFSSL_CRL_CHECKALL      = 1;
    /** CertManager: use override URL instead of URL in certificates */
    public static final int WOLFSSL_OCSP_URL_OVERRIDE = 1;
    /** CertManager: disable sending OCSP nonce */
    public static final int WOLFSSL_OCSP_NO_NONCE     = 2;

    /* ALPN definitions from ssl.h */
    /** ALPN: no match found */
    public static final int WOLFSSL_ALPN_NO_MATCH = 0;
    /** ALPN: found match */
    public static final int WOLFSSL_ALPN_MATCH    = 1;
    /** ALPN: continue on protocol mismatch */
    public static final int WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 2;
    /** ALPN: failed on protocol mismatch */
    public static final int WOLFSSL_ALPN_FAILED_ON_MISMATCH   = 4;

    /* I/O callback default errors, pulled from wolfssl/ssl.h IOerrors */
    /** I/O callback error: general error */
    public static final int WOLFSSL_CBIO_ERR_GENERAL    = -1;
    /** I/O callback error: want read */
    public static final int WOLFSSL_CBIO_ERR_WANT_READ  = -2;
    /** I/O callback error: want write */
    public static final int WOLFSSL_CBIO_ERR_WANT_WRITE = -2;
    /** I/O callback error: connection reset */
    public static final int WOLFSSL_CBIO_ERR_CONN_RST   = -3;
    /** I/O callback error: socket interrupted */
    public static final int WOLFSSL_CBIO_ERR_ISR        = -4;
    /** I/O callback error: connection closed */
    public static final int WOLFSSL_CBIO_ERR_CONN_CLOSE = -5;
    /** I/O callback error: timeout */
    public static final int WOLFSSL_CBIO_ERR_TIMEOUT    = -6;

    /* Atomic User Needs, from ssl.h */
    /** Represents server side */
    public static final int WOLFSSL_SERVER_END  = 0;
    /** Represents Client side */
    public static final int WOLFSSL_CLIENT_END  = 1;
    /** wolfSSL block algorithm type */
    public static final int WOLFSSL_BLOCK_TYPE  = 2;
    /** wolfSSL stream algorithm type */
    public static final int WOLFSSL_STREAM_TYPE = 3;
    /** wolfSSL AEAD algorithm type */
    public static final int WOLFSSL_AEAD_TYPE   = 4;
    /** wolfSSL TLS HMAC inner size */
    public static final int WOLFSSL_TLS_HMAC_INNER_SZ = 13;

    /* GetBulkCipher enum, pulled in from ssl.h for Atomic Record layer */
    /** Bulk cipher algorithm enum: NULL */
    public static int wolfssl_cipher_null;
    /** Bulk cipher algorithm enum: RC4 */
    public static int wolfssl_rc4;
    /** Bulk cipher algorithm enum: RC2 */
    public static int wolfssl_rc2;
    /** Bulk cipher algorithm enum: DES */
    public static int wolfssl_des;
    /** Bulk cipher algorithm enum: 3DES */
    public static int wolfssl_triple_des;
    /** Bulk cipher algorithm enum: DES40 */
    public static int wolfssl_des40;
    /** Bulk cipher algorithm enum: AES */
    public static int wolfssl_aes;
    /** Bulk cipher algorithm enum: AES-GCM */
    public static int wolfssl_aes_gcm;
    /** Bulk cipher algorithm enum: AES-CCM */
    public static int wolfssl_aes_ccm;

    /* wolfSSL error codes, pulled in from wolfssl/error.h wolfSSL_ErrorCodes */
    /** Generate Cookie Error */
    public static final int GEN_COOKIE_E    =   -277;

    /** Close notify alert sent */
    public static final int SSL_SENT_SHUTDOWN                   = 1;
    /** Close notify alert received */
    public static final int SSL_RECEIVED_SHUTDOWN               = 2;
    /** Make it possible to return SSL write with changed buffer location */
    public static final int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4;
    /** Disable SSL 2.0. wolfSSL does not support SSL 2.0. */
    public static final int SSL_OP_NO_SSLv2                     = 8;
    /** Disable SSL 3.0 */
    public static final int SSL_OP_NO_SSLv3                     = 0x00001000;
    /** Disable TLS 1.0 */
    public static final int SSL_OP_NO_TLSv1                     = 0x00002000;
    /** Disable TLS 1.1 */
    public static final int SSL_OP_NO_TLSv1_1                   = 0x04000000;
    /** Disable TLS 1.2 */
    public static final int SSL_OP_NO_TLSv1_2                   = 0x08000000;
    /** Disable TLS compression. Off by default */
    public static final int SSL_OP_NO_COMPRESSION               = 0x10000000;
    /** Disable TLS 1.3 */
    public static final int SSL_OP_NO_TLSv1_3                   = 0x20000000;

    /** SSL/TLS handshake failure */
    public static final int SSL_HANDSHAKE_FAILURE                 = 101;
    /** Alert: Unknown CA */
    public static final int SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102;
    /** Alert: Certificate Unknown */
    public static final int SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103;
    /** Alert: Bad certificate */
    public static final int SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104;

    /** Monitor this CRL directory flag */
    public static final int WOLFSSL_CRL_MONITOR   = 0x01;

    /** Start CRL monitoring flag */
    public static final int WOLFSSL_CRL_START_MON = 0x02;

    /** Bad mutex */
    public static final int BAD_MUTEX_ERROR      = -256;

    /** Bad path for opendir */
    public static final int BAD_PATH_ERROR       = -258;

    /** CRL Monitor already running */
    public static final int MONITOR_RUNNING_E    = -263;

    /** Thread create error */
    public static final int THREAD_CREATE_E      = -264;

    /** Cache header match error */
    public static final int CACHE_MATCH_ERROR    = -280;

    /* ------------------ TLS extension specific  ------------------------ */
    /** SNI Host name type, for UseSNI() */
    public static final int WOLFSSL_SNI_HOST_NAME = 0;

    /* ---------------------- wolfCrypt codes ---------------------------- */

    /** Out of memory error */
    public static final int MEMORY_E        = -125;

    /** Output buffer too small or input too large */
    public static final int BUFFER_E        = -132;

    /** ASN input error, not enough data */
    public static final int ASN_INPUT_E     = -154;

    /** Bad function argument provided */
    public static final int BAD_FUNC_ARG    = -173;

    /** Feature not compiled in */
    public static final int NOT_COMPILED_IN = -174;

    /** No password provided by user */
    public static final int NO_PASSWORD     = -176;

    /* hmac codes, from wolfssl/wolfcrypt/hmac.h */
    /** Md5 HMAC type */
    public static final int MD5   = 0;
    /** SHA-1 HMAC type */
    public static final int SHA   = 1;
    /** SHA2-256 HMAC type */
    public static final int SHA256 = 2;
    /** SHA2-512 HMAC type */
    public static final int SHA512 = 4;
    /** SHA2-384 HMAC type */
    public static final int SHA384 = 5;

    /* key types */
    /** DSA key type */
    public static final int DSAk     = 515;
    /** RSA key type */
    public static final int RSAk     = 645;
    /** NTRU key type */
    public static final int NTRUk    = 274;
    /** ECDSA key type */
    public static final int ECDSAk   = 518;
    /** Ed25519 key type */
    public static final int ED25519k = 256;

    /* is this object active, or has it been cleaned up? */
    private boolean active = false;

    /* ---------------------------- locks ------------------------------- */

    /* lock for cleanup */
    private final Object cleanupLock = new Object();

    /* ------------------------ constructors ---------------------------- */

    /**
     * Initializes the wolfSSL library for use.
     *
     * @throws com.wolfssl.WolfSSLException if wolfSSL library fails to
     *                                      initialize correctly
     */
    public WolfSSL() throws WolfSSLException {
        int ret = init();
        if (ret != SSL_SUCCESS) {
            throw new WolfSSLException("Failed to initialize wolfSSL library: "
                    + ret);
        }

        /* initialize enum values */
        wolfssl_aes         = getBulkCipherAlgorithmEnumAES();
        wolfssl_cipher_null = getBulkCipherAlgorithmEnumNULL();
        wolfssl_rc4         = getBulkCipherAlgorithmEnumRC4();
        wolfssl_rc2         = getBulkCipherAlgorithmEnumRC2();
        wolfssl_des         = getBulkCipherAlgorithmEnumDES();
        wolfssl_triple_des  = getBulkCipherAlgorithmEnumDES();
        wolfssl_des40       = getBulkCipherAlgorithmEnumDES40();
        wolfssl_aes_gcm     = getBulkCipherAlgorithmEnumAESGCM();
        wolfssl_aes_ccm     = getBulkCipherAlgorithmEnumAESCCM();

        this.active = true;
    }

    /* ------------------- private/protected methods -------------------- */

    private native int init();

    /**
     * Free native memory allocated at pointer provided.
     * @param ptr native pointer
     */
    public static native void nativeFree(long ptr);

    static native int getBulkCipherAlgorithmEnumNULL();
    static native int getBulkCipherAlgorithmEnumRC4();
    static native int getBulkCipherAlgorithmEnumRC2();
    static native int getBulkCipherAlgorithmEnumDES();
    static native int getBulkCipherAlgorithmEnum3DES();
    static native int getBulkCipherAlgorithmEnumDES40();
    static native int getBulkCipherAlgorithmEnumAES();
    static native int getBulkCipherAlgorithmEnumAESGCM();
    static native int getBulkCipherAlgorithmEnumAESCCM();
    static native int getBulkCipherAlgorithmEnumCHACHA();
    static native int getBulkCipherAlgorithmEnumCAMELLIA();

    static native String getEnabledCipherSuites();
    static native String getEnabledCipherSuitesIana();
    static native String getAvailableCipherSuitesIana(int version);

    /* ------------------------- Java methods --------------------------- */

    /**
     * Loads JNI library; must be called prior to any other calls in this class.
     *
     * The native library is expected to be be called "wolfssljni", and must be
     * on the system library search path.
     *
     * "wolfssljni" links against the wolfSSL native C library ("wolfssl"),
     * and for Windows compatibility "wolfssl" needs to be explicitly
     * loaded first here.
     *
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibrary() throws UnsatisfiedLinkError {

        int fipsLoaded = 0;

        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().contains("win")) {
            try {
                /* Default wolfCrypt FIPS library on Windows is compiled
                 * as "wolfssl-fips" by Visual Studio solution */
                System.loadLibrary("wolfssl-fips");
                fipsLoaded = 1;
            } catch (UnsatisfiedLinkError e) {
                /* wolfCrypt FIPS not available */
            }

            if (fipsLoaded == 0) {
                /* FIPS library not loaded, try normal libwolfssl */
                System.loadLibrary("wolfssl");
            }
        }

        /* Load wolfssljni library */
        System.loadLibrary("wolfssljni");
    }

    /**
     * Load JNI library with a specific name; must be called prior to any
     * other calls in this package.
     *
     * The native library needs to be located on the system library search
     * path.
     *
     * @param  libName name of native JNI library
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibrary(String libName) throws UnsatisfiedLinkError {
        System.loadLibrary(libName);
    }

    /**
     * Loads dynamic JNI library from a specific path; must be called prior to
     * any other calls in this package.
     *
     * This function gives the application more control over the exact native
     * library being loaded, as both WolfSSL.loadLibrary() and
     * WolfSSL.loadLibrary(String libName) search for a library on the system
     * library search path. This function allows the appliation to specify
     * a specific absolute path to the native library file to load, thus
     * guaranteeing the exact library loaded and helping to prevent against
     * malicious attackers from attempting to override the library being
     * loaded.
     *
     * @param  libPath complete path name to the native dynamic JNI library
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibraryAbsolute(String libPath)
        throws UnsatisfiedLinkError {
        System.load(libPath);
    }

    /* --------------- native feature detection functions --------------- */

    /**
     * Tests if TLS 1.0 has been compiled into the native wolfSSL library.
     * TLS 1.0 is disabled by default in native wolfSSL, unless the user
     * has configured wolfSSL with "--enable-tls10".
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv1Enabled();

    /**
     * Tests if TLS 1.1 has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv11Enabled();

    /**
     * Tests if TLS 1.2 has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv12Enabled();

    /**
     * Tests if TLS 1.3 has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean TLSv13Enabled();

    /**
     * Tests if ECC support has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean EccEnabled();

    /**
     * Tests if RSA support has been compiled into the native wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if not compiled in.
     */
    public static native boolean RsaEnabled();

    /**
     * Tests if filesystem support has been compiled into the wolfSSL library.
     *
     * @return 1 if enabled, otherwise 0 if NO_FILESYSTEM has been defined.
     */
    public static native boolean FileSystemEnabled();

    /* ---------------- native SSL/TLS version functions ---------------- */

    /**
     * Indicates that the application is a server and will only support the
     * SSL 3.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     * @deprecated SSL 3.0 is now considered insecure.
     */
    @Deprecated
    public static final native long SSLv3_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * SSL 3.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     * @deprecated SSL 3.0 is now considered insecure.
     */
    @Deprecated
    public static final native long SSLv3_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.0 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.1 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.1 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.1 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_1_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.2 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_2_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_2_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_2_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.3 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_3_Method();

    /**
     * Indicates that the application will only support the DTLS 1.0 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * DTLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * DTLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_ClientMethod();

    /**
     * Indicates that the application will only support the DTLS 1.2 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_2_Method();

    /**
     * Indicates that the application is a server and will only support the
     * DTLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_2_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * DTLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_2_ClientMethod();

    /**
     * Indicates that the application will use the highest possible SSL/TLS
     * version from SSL 3.0 up to TLS 1.2, but is side-independent at creation
     * time. Client/server side will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long SSLv23_Method();

    /**
     * Indicates that the application is a server and will use the highest
     * possible SSL/TLS version from SSL 3.0 up to TLS 1.2.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long SSLv23_ServerMethod();

    /**
     * Indicates that the application is a client and will use the highest
     * possible SSL/TLS version from SSL 3.0 up to TLS 1.2.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long SSLv23_ClientMethod();

    /**
     * Converts an error code returned by getError() into a more human-
     * readable error string.
     * The maximum length of the returned string is 80 characters by
     * default, as defined by MAX_ERROR_SZ in the native wolfSSL
     * error.h header file.
     *
     * @param errNumber     error code returned by <code>getError()</code>
     * @return              output String containing human-readable error
     *                      string matching <code>errNumber</code>
     *                      on success. On failure, this method returns a
     *                      String with the appropriate failure reason.
     * @see                 WolfSSLSession#getError(long, int)
     */
    public static final native String getErrorString(long errNumber);

    /**
     * Un-initializes the wolfSSL library from further use.
     * Doesn't have to be called, though it will free any resources used by
     * the library.
     *
     * @return <code>SSL_SUCCESS</code> upon success, <code>BAD_MUTEX_ERROR
     *         </code> on mutex error.
     */
    public static final native int cleanup();

    /**
     * Turns on debug logging at runtime.
     * To enable logging at build time, use <b>--enable-debug</b> or define
     * <b>DEBUG_WOLFSSL</b>. Debugging must be enabled at build time in order
     * for the method to have any effect.
     *
     * @return  <code>SSL_SUCCESS</code> upon success. <code>NOT_COMPILED_IN
     *          </code> if logging isnt' enabled for this wolfSSL build.
     * @see     #debuggingOFF()
     * @see     #setLoggingCb(WolfSSLLoggingCallback)
     */
    public static final native int debuggingON();

    /**
     * Turns off runtime debug log messages.
     * If they're already off, no action is taken.
     *
     * @see #debuggingON()
     * @see #setLoggingCb(WolfSSLLoggingCallback)
     */
    public static final native void debuggingOFF();

    /**
     * Registers the callback to be used for Logging debug and trace
     * messages.
     *
     * @param cb    Callback to be used for logging debug messages
     * @return      <b><code>SSL_ERROR_NONE</code></b> upon success,
     *              <b><code>BAD_FUNC_ARG</code></b> if input is null,
     *              <b><code>NOT_COMPILED_IN</code></b> if wolfSSL was not
     *              compiled with debugging support enabled.
     * @see         #debuggingON()
     * @see         #debuggingOFF()
     */
    public static final native int setLoggingCb(WolfSSLLoggingCallback cb);

    /**
     * Registers the callback to be used for wolfCrypt FIPS verifyCore error.
     * This method is a NOOP if called when not using a wolfCrypt FIPS
     * library.
     *
     * @param cb    Callback to be used for wolfCrypt FIPS verifyCore errors
     * @return      <b><code>SSL_SUCCESS</code></b> on success,
     *              <b><code>NOT_COMPILED_IN</code></b> if not using wolfCrypt
     *              FIPS library distribution, or negative on error.
     */
    public static final native int setFIPSCb(WolfSSLFIPSErrorCallback cb);


    /**
     * Returns the current verifyCore hash from wolfCrypt FIPS, from
     * native wolfcrypt/src/fips_test.c, verifyCore[] array.
     *
     * NOTE: this method returns NULL if not used with a wolfCrypt FIPS
     * library.
     *
     * @return current verifyCore hash from wolfCrypt FIPS, or NULL
     *         if called when not using a wolfCrypt FIPS library.
     */
    public static final native String getWolfCryptFIPSCoreHash();

    /**
     * Persists session cache to memory buffer.
     * This method can be used to persist the current session cache to a
     * memory buffer for storage. The cache can be loaded back into wolfSSL
     * using the corresponding <code>memrestoreSessionCache()</code> method.
     *
     * @param mem   buffer to store session cache in
     * @param sz    size of the input buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> on success,
     *              <b><code>SSL_FAILURE</code></b> on general failure,
     *              <b><code>BUFFER_E</code></b> if the memory buffer is too
     *              small to store the session cache in,
     *              <b><code>BAD_MUTEX_ERROR</code></b> if the session cache
     *              mutex lock failed,
     *              <b><code>BAD_FUNC_ARG</code></b> if invalid parameters are
     *              used.
     * @see         #memrestoreSessionCache(byte[], int)
     * @see         #getSessionCacheMemsize()
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int memsaveSessionCache(byte[] mem, int sz);

    /**
     * Restores the persistant session cache from memory buffer.
     * This function restores a session cache that was previously saved to
     * a memory buffer.
     *
     * @param mem   buffer containing persistant session cache to be restored
     * @param sz    size of the input buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> upon success,
     *              <b><code>SSL_FAILURE</code></b> upon general failure,
     *              <b><code>BUFFER_E</code></b> if the memory buffer is too
     *              small, <b><code>CACHE_MATCH_ERROR</code></b> if the
     *              session cache header match failed and there were
     *              differences in how the cache and the current library
     *              are configured, <b><code>BAD_MUTEX_ERROR</code></b>
     *              if the session cache mutex lock failed,
     *              <b><code>BAD_FUNC_ARG</code></b> if invalid parameters are
     *              used.
     * @see         #memsaveSessionCache(byte[], int)
     * @see         #getSessionCacheMemsize()
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int memrestoreSessionCache(byte[] mem, int sz);

    /**
     * Gets how big the session cache save buffer needs to be.
     * Use this method to determine how large the buffer needs to be to
     * store the persistant session cache into memory.
     *
     * @return      size, in bytes, of how large the output buffer should be
     *              to store the session cache into memory.
     * @see         #memsaveSessionCache(byte[], int)
     * @see         #memrestoreSessionCache(byte[], int)
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int getSessionCacheMemsize();

    /**
     * Strips off PKCS#8 header from byte array.
     * This function starts reading the input array for a PKCS#8 header,
     * beginning at input offset, idx. If found, it returns the offset of
     * the inner traditional data.
     *
     * @param in  input buffer containing PKCS#8 formatted key
     * @param idx index/offset into input array to begin reading
     * @param sz  size of input array
     * @return    offset where the traditional key begins, or negative on
     *            failure.
     */
    public static native int getPkcs8TraditionalOffset(byte[] in, long idx,
        long sz);

    /**
     * Returns the DER-encoded form of the certificate pointed to by
     * x509.
     *
     * @param x509      pointer (long) to a native WOLFSSL_X509 object. This
     *                  objects represents an X.509 certificate.
     * @return          DER-encoded certificate or
     *                  <code>null</code> if the input buffer is null.
     *
     */
    public static native byte[] x509_getDer(long x509);

    /**
     * Returns the wolfSSL max HMAC digest size.
     * Specifically, returns the value of the native wolfSSL
     * MAX_DIGEST_SIZE define.
     *
     * @return  value of native MAX_DIGEST_SIZE define
     */
    public static native int getHmacMaxSize();

    /**
     * Returns the enabled cipher suites for native wolfSSL.
     *
     * @return array of cipher suite Strings
     */
    public static String[] getCiphers() {

        String cipherSuites = getEnabledCipherSuites();
        if (cipherSuites == null)
            return null;

        return cipherSuites.split(":");
    }

    /**
     * Gets a list of all cipher suites supported by native wolfSSL and
     * uses the format TLS_*. This list may not be in priority order. If
     * priority order is desired, see getCiphersAvailableIana().
     * @return list of all cipher suites supported
     */
    public static String[] getCiphersIana() {
        String cipherSuites = getEnabledCipherSuitesIana();
        if (cipherSuites == null)
            return null;

        return cipherSuites.split(":");
    }

    /**
     * Gets a list of all cipher suites available for current native wolfSSL
     * configuration and selected protocol level. In the format TLS_*.
     *
     * @param version protocol version for which to get cipher suites.
     * @return list of cipher suites.
     */
    public static String[] getCiphersAvailableIana(TLS_VERSION version) {
        /* passing Enum as ordinal to JNI layer, see com_wolfssl_WolfSSL.c */
        String cipherSuites = getAvailableCipherSuitesIana(version.ordinal());
        if (cipherSuites == null)
            return null;

        return cipherSuites.split(":");
    }

    /**
     * Checks which protocols were built into wolfSSL
     *
     * @return an array of Strings for supported protocols
     */
    public static native String[] getProtocols();

    /**
     * Checks which protocols were built into wolfSSL with Mask
     *
     * @param mask flags prohibiting TLS version (i.e. SSL_OP_NO_xxx)
     * @return an array of Strings for supported protocols
     */
    public static native String[] getProtocolsMask(long mask);

    /**
     * Return number of active sessions in local session cache.
     *
     * To use this API native wolfSSL must be compiled with
     * WOLFSSL_SESSION_STATS.
     *
     * @return number of sessions active or negative on error
     */
    public static native int getSessionStatsActive();

    /**
     * Return number of total sessions seen in local session cache.
     *
     * To use this API native wolfSSL must be compiled with
     * WOLFSSL_SESSION_STATS.
     *
     * @return number of total sessions seen or negative on error
     */
    public static native int getSessionStatsTotal();

    /**
     * Return number of peak sessions in local session cache.
     *
     * To use this API native wolfSSL must be compiled with
     * WOLFSSL_SESSION_STATS.
     *
     * @return number of peak sessions or negative on error
     */
    public static native int getSessionStatsPeak();

    /**
     * Return number of max sessions in local session cache.
     *
     * To use this API native wolfSSL must be compiled with
     * WOLFSSL_SESSION_STATS.
     *
     * @return number of max sessions or negative on error
     */
    public static native int getSessionStatsMaxSessions();

    /* ------------------------- isEnabled methods -------------------------- */

    /**
     * Checks if CRL support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledCRL();

    /**
     * Checks if CRL Monitor support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledCRLMonitor();

    /**
     * Checks if OCSP support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledOCSP();

    /**
     * Checks if PSK support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledPSK();

    /**
     * Checks if DTLS support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledDTLS();

    /**
     * Checks if Atomic User support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledAtomicUser();

    /**
     * Checks if Public Key Callback support is enabled in wolfSSL
     * native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledPKCallbacks();

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        synchronized(cleanupLock) {
            if (this.active == true) {
                /* free resources, set state */
                this.cleanup();
                this.active = false;
            }
        }
        super.finalize();
    }

} /* end WolfSSL */


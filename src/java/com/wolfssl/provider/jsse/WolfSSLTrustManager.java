/* WolfSSLTrustManager.java
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

package com.wolfssl.provider.jsse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * wolfSSL implemenation of TrustManagerFactorySpi
 *
 * @author wolfSSL
 */
public class WolfSSLTrustManager extends TrustManagerFactorySpi {
    private KeyStore store;

    @Override
    protected void engineInit(KeyStore in) throws KeyStoreException {
        KeyStore certs = in;
        if (in == null) {
            String pass = System.getProperty("javax.net.ssl.trustStorePassword");
            String file = System.getProperty("javax.net.ssl.trustStore");
            char passAr[] = null;
            InputStream stream = null;
            boolean systemCertsFound = false;

            try {
                if (pass != null) {
                    passAr = pass.toCharArray();
                }
                certs = KeyStore.getInstance("JKS");
                if (file == null) {
                    /* try to load trusted system certs if possible */
                    String home = System.getenv("JAVA_HOME");
                    if (home != null) {
                        if (!home.endsWith("/") && !home.endsWith("\\")) {
                            /* add trailing slash if not there already */
                            home = home.concat("/");
                        }

                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "$JAVA_HOME = " + home);

                        /* trying: "lib/security/jssecacerts" */
                        File f = new File(home.concat(
                                            "jre/lib/security/jssecacerts"));
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Loading certs from " +
                                    home.concat("lib/security/jssecacerts"));
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        }

                        /* trying: "lib/security/cacerts" */
                        f = new File(home.concat("jre/lib/security/cacerts"));
                        if (f.exists()) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "Loading certs from " +
                                    home.concat("lib/security/cacerts"));
                            stream = new FileInputStream(f);
                            certs.load(stream, passAr);
                            stream.close();
                            systemCertsFound = true;
                        }

                        if (systemCertsFound == false) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                    "No trusted system certs found, " +
                                    "using Anonymous cipher suite");
                        }
                    }
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Loading certs from " + file);
                    stream = new FileInputStream(file);
                    certs.load(stream, passAr);
                    stream.close();
                }
            } catch (FileNotFoundException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(
                        WolfSSLTrustManager.class.getName()).log(
                            Level.SEVERE, null, ex);
            }
        }
        this.store = certs;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0)
        throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        /* array of WolfSSLX509Trust objects to use */
        TrustManager[] tm = {new WolfSSLTrustX509(this.store)};
        return tm;
    }
}

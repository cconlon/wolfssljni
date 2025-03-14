/* WolfSSLSessionContext.java
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

package com.wolfssl.provider.jsse;

import java.util.Enumeration;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import com.wolfssl.WolfSSL;

/**
 * WolfSSLSessionContext class
 *
 * @author wolfSSL Inc.
 */
public class WolfSSLSessionContext implements SSLSessionContext {
    private WolfSSLAuthStore store = null;
    private int sesTimout = 0;
    private int sesCache = 0;
    private int side = WolfSSL.WOLFSSL_CLIENT_END;

    /**
     * Create new WolfSSLSessionContext
     *
     * WolfSSLAuthStore not given as parameter in this constructor, caller
     * should explicitly set with WolfSSLSessionContext.setWolfSSLAuthStore().
     *
     * @param defaultCacheSize default session cache size
     * @param side client or server side. Either WolfSSL.WOLFSSL_CLIENT_END or
     *        WolfSSL.WOLFSSL_SERVER_END
     */
    public WolfSSLSessionContext(int defaultCacheSize, int side) {
        this.sesCache  = defaultCacheSize;
        this.sesTimout = 86400; /* this is the default value in SunJSSE too */
        this.side      = side;
    }

    /**
     * Create new WolfSSLSessionContext
     *
     * @param in WolfSSLAuthStore object to use with this context
     * @param defaultCacheSize default session cache size
     * @param side client or server side. Either WolfSSL.WOLFSSL_CLIENT_END or
     *        WolfSSL.WOLFSSL_SERVER_END
     */
    public WolfSSLSessionContext(WolfSSLAuthStore in, int defaultCacheSize,
            int side) {
        this.store     = in;
        this.sesCache  = defaultCacheSize;
        this.sesTimout = 86400; /* this is the default value in SunJSSE too */
        this.side      = side;
    }

    /**
     * Set WolfSSLAuthStore for this object.
     *
     * @param store WolfSSLAuthStore to use with this object
     */
    public void setWolfSSLAuthStore(WolfSSLAuthStore store) {
        this.store = store;
    }

    @Override
    public SSLSession getSession(byte[] sessionId) {
        if (store == null) {
            return null;
        }
        return store.getSession(sessionId, side);
    }


    @Override
    public Enumeration<byte[]> getIds() {
        if (store == null) {
            return null;
        }
        return store.getAllIDs(side);
    }


    @Override
    public void setSessionTimeout(int in) throws IllegalArgumentException {
        this.sesTimout = in;

        /* check for any new timeouts after timeout has been set */
        if (store != null) {
            store.updateTimeouts(in, this.side);
        }
    }

    @Override
    public int getSessionTimeout() {
        return this.sesTimout;
    }


    @Override
    public void setSessionCacheSize(int in)
        throws IllegalArgumentException {

        if (in < 0) {
            throw new IllegalArgumentException("size can not be less than 0");
        }

        /* resize store array if needed */
        if ((store != null) && (this.sesCache != in)) {
            store.resizeCache(in, this.side);
        }
        this.sesCache = in;
    }

    @Override
    public int getSessionCacheSize() {
        return this.sesCache;
    }
}

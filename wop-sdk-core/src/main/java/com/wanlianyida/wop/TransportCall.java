package com.wanlianyida.wop;

import java.util.Objects;

public final class TransportCall {

    public static final int USE_DEFAULT = -1;

    private final String serverRoot;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    private TransportCall(String serverRoot, int connectTimeoutMillis, int readTimeoutMillis) {
        this.serverRoot = serverRoot;
        this.connectTimeoutMillis = connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis;
    }

    public static TransportCall empty() {
        return new TransportCall(null, USE_DEFAULT, USE_DEFAULT);
    }

    public static TransportCall of(String serverRoot, int connectTimeoutMillis, int readTimeoutMillis) {
        return new TransportCall(serverRoot, connectTimeoutMillis, readTimeoutMillis);
    }

    /** 目标网关根地址；null = 适配器构造期 baseUrl。 */
    public String serverRoot() {
        return serverRoot;
    }

    public int connectTimeoutMillis() {
        return connectTimeoutMillis;
    }

    public int readTimeoutMillis() {
        return readTimeoutMillis;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof TransportCall)) {
            return false;
        }
        TransportCall that = (TransportCall) o;
        return connectTimeoutMillis == that.connectTimeoutMillis
                && readTimeoutMillis == that.readTimeoutMillis
                && Objects.equals(serverRoot, that.serverRoot);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverRoot, connectTimeoutMillis, readTimeoutMillis);
    }
}

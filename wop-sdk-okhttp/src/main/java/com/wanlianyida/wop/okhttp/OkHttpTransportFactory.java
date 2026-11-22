package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;

public final class OkHttpTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "okhttp";
    }

    @Override
    public Transport create(String serverRoot) {
        return new OkHttpTransport(serverRoot);
    }
}

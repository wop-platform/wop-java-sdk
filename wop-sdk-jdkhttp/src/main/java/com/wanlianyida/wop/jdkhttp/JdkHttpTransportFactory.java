package com.wanlianyida.wop.jdkhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;

public final class JdkHttpTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "jdkhttp";
    }

    @Override
    public Transport create(String serverRoot) {
        return new JdkHttpTransport(serverRoot);
    }
}

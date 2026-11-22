package com.wanlianyida.wop.unirest;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;

public final class UnirestTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "unirest";
    }

    @Override
    public Transport create(String serverRoot) {
        return new UnirestTransport(serverRoot);
    }
}

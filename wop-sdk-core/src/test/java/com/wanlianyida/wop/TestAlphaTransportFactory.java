package com.wanlianyida.wop;

public final class TestAlphaTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "alpha";
    }

    @Override
    public Transport create(String serverRoot) {
        return new TestStubTransport();
    }
}

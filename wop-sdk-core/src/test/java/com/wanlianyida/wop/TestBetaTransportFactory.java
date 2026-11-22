package com.wanlianyida.wop;

public final class TestBetaTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "beta";
    }

    @Override
    public Transport create(String serverRoot) {
        return new TestStubTransport();
    }
}

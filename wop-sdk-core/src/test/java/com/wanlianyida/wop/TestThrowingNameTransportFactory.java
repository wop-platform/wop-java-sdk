package com.wanlianyida.wop;

public final class TestThrowingNameTransportFactory implements TransportFactory {

    @Override
    public String name() {
        throw new IllegalStateException("name() 故意失败");
    }

    @Override
    public Transport create(String serverRoot) {
        return new TestStubTransport();
    }
}

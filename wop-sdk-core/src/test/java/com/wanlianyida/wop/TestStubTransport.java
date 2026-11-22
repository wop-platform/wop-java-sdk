package com.wanlianyida.wop;

public final class TestStubTransport implements Transport {

    @Override
    public TransportResponse send(RequestDraft draft) {
        throw new UnsupportedOperationException("test stub");
    }
}

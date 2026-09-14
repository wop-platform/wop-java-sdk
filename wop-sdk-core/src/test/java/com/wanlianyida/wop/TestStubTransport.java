package com.wanlianyida.wop;

/** 测试桩 Transport：SPI 发现测试不发送请求，create() 仅作返回占位。 */
public final class TestStubTransport implements Transport {

    @Override
    public TransportResponse send(RequestDraft draft) {
        throw new UnsupportedOperationException("test stub");
    }
}

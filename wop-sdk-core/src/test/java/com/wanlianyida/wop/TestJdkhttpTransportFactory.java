package com.wanlianyida.wop;

/** 测试 factory（jdkhttp 名）：验证 P2 多 factory 时 jdkhttp 默认选中。 */
public final class TestJdkhttpTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "jdkhttp";
    }

    @Override
    public Transport create(String serverRoot) {
        return new TestStubTransport();
    }
}

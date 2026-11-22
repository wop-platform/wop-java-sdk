package com.wanlianyida.wop;

/**
 * 测试 factory（alpha）：仅经 core 测试 classpath 的 META-INF/services 注册，
 * 与 {@link TestBetaTransportFactory} 共同制造「多个 factory」态
 * （config-spec §2.2/K18，§13.1 测试点 1）。
 */
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

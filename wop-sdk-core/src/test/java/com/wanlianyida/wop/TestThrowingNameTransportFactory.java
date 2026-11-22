package com.wanlianyida.wop;

/**
 * 测试 factory（name() 抛错）：与 alpha 共同制造「多 factory 且 name() 失败」态，
 * 验证多 factory 列名路径上单个注册项的运行时异常被包装为
 * {@code WopError.configuration}（含 cause），不让第三方 factory 的原生异常
 * 越过 SPI 边界（config-spec §2.2/K18，PR#35 评审语义）。
 */
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

package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/**
 * okhttp TransportFactory SPI 恰一态（config-spec §2.2/K18，§13.1 测试点 1）：
 * 本模块测试 classpath 仅注册本 factory——发现即命中且唯一；create() 产出本适配器传输实例。
 */
class OkHttpTransportFactoryTest {

    @Test
    void spiRegistersExactlyOneFactory() {
        assertEquals("okhttp", TransportFactory.discover().name());
    }

    @Test
    void createBuildsOkHttpTransport() {
        TransportFactory factory = TransportFactory.discover();
        assertInstanceOf(OkHttpTransport.class, factory.create("https://gw.example.com/gtsp-wop-gateway"));
        // serverRoot 可空（与适配器 baseUrl 构造器语义一致）
        assertInstanceOf(OkHttpTransport.class, factory.create(null));
    }
}

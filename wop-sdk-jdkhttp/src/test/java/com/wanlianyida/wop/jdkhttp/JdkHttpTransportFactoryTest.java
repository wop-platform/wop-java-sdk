package com.wanlianyida.wop.jdkhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class JdkHttpTransportFactoryTest {

    @Test
    void spiRegistersExactlyOneFactory() {
        assertEquals("jdkhttp", TransportFactory.discover().name());
    }

    @Test
    void createBuildsJdkHttpTransport() {
        TransportFactory factory = TransportFactory.discover();
        assertInstanceOf(JdkHttpTransport.class, factory.create("https://gw.example.com/gtsp-wop-gateway"));
        assertInstanceOf(JdkHttpTransport.class, factory.create(null));
    }
}

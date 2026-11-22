package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class OkHttpTransportFactoryTest {

    @Test
    void spiRegistersExactlyOneFactory() {
        assertEquals("okhttp", TransportFactory.discover().name());
    }

    @Test
    void createBuildsOkHttpTransport() {
        TransportFactory factory = TransportFactory.discover();
        assertInstanceOf(OkHttpTransport.class, factory.create("https://gw.example.com/gtsp-wop-gateway"));
        assertInstanceOf(OkHttpTransport.class, factory.create(null));
    }
}

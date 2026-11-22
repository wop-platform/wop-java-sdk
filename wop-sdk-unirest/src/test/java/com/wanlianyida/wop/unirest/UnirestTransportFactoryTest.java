package com.wanlianyida.wop.unirest;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class UnirestTransportFactoryTest {

    @Test
    void spiRegistersExactlyOneFactory() {
        assertEquals("unirest", TransportFactory.discover().name());
    }

    @Test
    void createBuildsUnirestTransport() {
        TransportFactory factory = TransportFactory.discover();
        assertInstanceOf(UnirestTransport.class, factory.create("https://gw.example.com/gtsp-wop-gateway"));
        assertInstanceOf(UnirestTransport.class, factory.create(null));
    }
}

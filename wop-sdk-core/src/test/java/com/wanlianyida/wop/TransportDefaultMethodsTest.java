package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** Transport 接口默认方法：双参 send 委托单参、supportsTransportCall 默认 false。 */
class TransportDefaultMethodsTest {

    @Test
    void twoArgSendDelegatesToSingleArg() {
        Transport transport = d -> new TransportResponse(204, Collections.emptyMap(), new byte[0]);
        TransportResponse resp = transport.send(
                new RequestDraft("POST", "/gateway/x", new LinkedHashMap<String, String>(), null),
                TransportCall.empty());
        assertEquals(204, resp.statusCode());
    }

    @Test
    void supportsTransportCallDefaultsToFalse() {
        Transport transport = d -> new TransportResponse(200, Collections.emptyMap(), new byte[0]);
        assertFalse(transport.supportsTransportCall());
    }
}

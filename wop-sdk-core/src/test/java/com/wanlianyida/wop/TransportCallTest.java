package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** TransportCall 值语义（USE_DEFAULT 哨兵、empty/of、equals 三字段矩阵）。 */
class TransportCallTest {

    @Test
    void useDefaultSentinel() {
        assertEquals(-1, TransportCall.USE_DEFAULT);
    }

    @Test
    void emptyAndOfAccessors() {
        TransportCall empty = TransportCall.empty();
        assertNull(empty.serverRoot());
        assertEquals(TransportCall.USE_DEFAULT, empty.connectTimeoutMillis());
        assertEquals(TransportCall.USE_DEFAULT, empty.readTimeoutMillis());
        TransportCall of = TransportCall.of("https://gw.example.com/gateway", 1500, 2500);
        assertEquals("https://gw.example.com/gateway", of.serverRoot());
        assertEquals(1500, of.connectTimeoutMillis());
        assertEquals(2500, of.readTimeoutMillis());
    }

    @Test
    void equalsMatrix() {
        TransportCall base = TransportCall.of("https://gw.example.com/gateway", 1500, 2500);
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, "x");
        assertEquals(base, TransportCall.of("https://gw.example.com/gateway", 1500, 2500));
        assertNotEquals(base, TransportCall.of("https://other.example.com/gateway", 1500, 2500));
        assertNotEquals(base, TransportCall.of("https://gw.example.com/gateway", 1, 2500));
        assertNotEquals(base, TransportCall.of("https://gw.example.com/gateway", 1500, 1));
        // empty() 与值等的 of(null, -1, -1) 语义一致
        assertEquals(TransportCall.empty(),
                TransportCall.of(null, TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT));
    }

    @Test
    void hashCodeConsistentWithEquals() {
        assertEquals(TransportCall.of("https://gw.example.com/gateway", 1500, 2500).hashCode(),
                TransportCall.of("https://gw.example.com/gateway", 1500, 2500).hashCode());
    }
}

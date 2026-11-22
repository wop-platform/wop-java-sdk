package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** WopGatewayResponseException 状态快照、消息与双向防御拷贝。 */
class WopGatewayResponseExceptionTest {

    @Test
    void nullBodyReportsZeroBytes() {
        WopGatewayResponseException e = new WopGatewayResponseException(500, null);
        assertEquals(500, e.statusCode());
        assertEquals(0, e.body().length);
        assertTrue(e.getMessage().contains("HTTP 500"));
        assertTrue(e.getMessage().contains("响应体 0 字节"));
    }

    @Test
    void bodySnapshotAndAccessors() {
        WopGatewayResponseException e = new WopGatewayResponseException(502,
                "bad".getBytes(StandardCharsets.UTF_8));
        assertEquals(502, e.statusCode());
        assertEquals("bad", new String(e.body(), StandardCharsets.UTF_8));
        assertTrue(e.getMessage().contains("HTTP 502"));
        assertTrue(e.getMessage().contains("响应体 3 字节"));
    }

    @Test
    void bodyDefensivelyCopiedBothWays() {
        byte[] in = "abc".getBytes(StandardCharsets.UTF_8);
        WopGatewayResponseException e = new WopGatewayResponseException(500, in);
        in[0] = 'x';
        assertEquals((byte) 'a', e.body()[0]);
        e.body()[0] = 'y';
        assertEquals((byte) 'a', e.body()[0]);
    }
}

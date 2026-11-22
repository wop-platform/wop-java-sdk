package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.DekPayload;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

class CoverageEdge3Test {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private static WopClient testClient() {
        LongSupplier clock = () -> 1_758_900_000_000L;
        Supplier<String> nonce = () -> "fixed00000000000000000000000000a";
        return new WopClient(new WopClient.Config(
                "app_001", AlgorithmSuite.parse("WOP-RSA3072-SHA256"),
                RSA_PRIV, RSA_PUB, 1800), clock, nonce);
    }


    @Test
    void codecNullInputs() {
        assertEquals("", Codec.hexLower(null));
        assertArrayEquals(new byte[0], Codec.utf8(null));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode(null));
        assertFalse(Codec.isLowerHex64(null));
    }

    @Test
    void codecB64UrlCharClassBoundaries() {
        assertEquals(6, Codec.b64UrlDecode("AZaz09-_").length);
        byte[] data = "边界测试!".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(data, Codec.b64UrlDecode(Codec.b64UrlEncode(data)));
        for (char bad : new char[]{'@', '[', '`', '{', '/', ':', '=', '+', ' ', '%'}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Codec.b64UrlDecode("abc" + bad),
                    "非法字符 " + bad + " 应拒绝");
        }
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("abcde"));
    }

    @Test
    void codecConcatEmptyParts() {
        assertArrayEquals(new byte[0], Codec.concat());
        assertArrayEquals(new byte[]{1, 2}, Codec.concat(new byte[]{1}, new byte[]{2}));
    }


    private static DekPayload validPayload() {
        return new DekPayload("AES256-GCM",
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    }

    @Test
    void dekPayloadEncodeNullPayload() {
        // spec:2.2 配置/解析错误闭集：DEK 载荷编码为 parse 类
        WopError ex = assertThrows(WopError.class, () -> DekPayload.encode(null));
        assertEquals(WopError.Category.parse, ex.category());
    }

    @Test
    void dekPayloadEncodeMissingFields() {
        byte[] k = validPayload().key();
        byte[] iv = validPayload().iv();
        assertThrows(WopError.class,
                () -> DekPayload.encode(new DekPayload(null, k, iv)));
        assertThrows(WopError.class,
                () -> DekPayload.encode(new DekPayload("   ", k, iv)));
        assertThrows(WopError.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", null, iv)));
        assertThrows(WopError.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", new byte[0], iv)));
        assertThrows(WopError.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", k, null)));
        assertThrows(WopError.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", k, new byte[0])));
    }

    @Test
    void dekPayloadEncodeDecodeRoundTrip() {
        DekPayload p = validPayload();
        String encoded = DekPayload.encode(p);
        DekPayload back = DekPayload.decode(encoded);
        assertEquals("AES256-GCM", back.alg());
        assertArrayEquals(p.key(), back.key());
        assertArrayEquals(p.iv(), back.iv());
        // toString 不含 key 明文
        assertFalse(p.toString().contains("010203"));
        assertTrue(p.toString().contains("-hidden"));
    }

    @Test
    void dekPayloadDecodeMalformed() {
        assertThrows(WopError.class, () -> DekPayload.decode(null));
        assertThrows(WopError.class, () -> DekPayload.decode(""));
        assertThrows(WopError.class, () -> DekPayload.decode("a$b"));
        assertThrows(WopError.class, () -> DekPayload.decode("a$b$c$d"));
        assertThrows(WopError.class, () -> DekPayload.decode("$AAAA$BBBB"));
        assertThrows(WopError.class,
                () -> DekPayload.decode("AES256-GCM$!!!$AAAA"));
        assertThrows(WopError.class,
                () -> DekPayload.decode("AES256-GCM$AAAA$==="));
    }


    @Test
    void buildRequestEmptyByteArrayBodyIsNoBody() {
        WopClient client = testClient();
        RequestDraft draft = client.buildRequest("POST", "/gateway/test", new byte[0], SecurityLevel.L0);
        assertNull(draft.wireBody());
        assertNull(draft.headers().get("x-wop-content-digest"));
        // L2 + 空数组：拒绝（L2 需要非空 body）
        assertThrows(WopError.class,
                () -> client.buildRequest("POST", "/gateway/test", new byte[0], SecurityLevel.L2));
    }
}

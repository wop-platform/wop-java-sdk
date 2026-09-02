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

/**
 * 覆盖率 100% 闭合测试（spec v1.0 使用场景边界）：
 * 覆盖 DekPayload.encode 字段缺失全分支、Codec 字符类边界、buildRequest 空数组 body 路径。
 */
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

    // ==================== Codec 边界（isB64UrlChar 字符类全覆盖） ====================

    @Test
    void codecNullInputs() {
        assertEquals("", Codec.hexLower(null));
        assertArrayEquals(new byte[0], Codec.utf8(null));
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode(null));
        assertFalse(Codec.isLowerHex64(null));
    }

    @Test
    void codecB64UrlCharClassBoundaries() {
        // 4 个字符类边界：A/Z、a/z、0/9、-/_ 全量合法（8 字符 → 6 字节）
        assertEquals(6, Codec.b64UrlDecode("AZaz09-_").length);
        // 编码往返：字节级一致
        byte[] data = "边界测试!".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(data, Codec.b64UrlDecode(Codec.b64UrlEncode(data)));
        // 越界字符：大写后 '@' 与 '['、小写后 '`' 与 '{'、数字前后 '/' 与 ':'、符号 '=' '+'
        for (char bad : new char[]{'@', '[', '`', '{', '/', ':', '=', '+', ' ', '%'}) {
            assertThrows(IllegalArgumentException.class,
                    () -> Codec.b64UrlDecode("abc" + bad),
                    "非法字符 " + bad + " 应拒绝");
        }
        // 长度 mod 4 == 1 拒绝
        assertThrows(IllegalArgumentException.class, () -> Codec.b64UrlDecode("abcde"));
    }

    @Test
    void codecConcatEmptyParts() {
        assertArrayEquals(new byte[0], Codec.concat());
        assertArrayEquals(new byte[]{1, 2}, Codec.concat(new byte[]{1}, new byte[]{2}));
    }

    // ==================== DekPayload.encode/decode 全分支 ====================

    private static DekPayload validPayload() {
        return new DekPayload("AES256-GCM",
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
                new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
    }

    @Test
    void dekPayloadEncodeNullPayload() {
        assertThrows(WopSdkException.class, () -> DekPayload.encode(null));
    }

    @Test
    void dekPayloadEncodeMissingFields() {
        byte[] k = validPayload().key();
        byte[] iv = validPayload().iv();
        // alg null / blank
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload(null, k, iv)));
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("   ", k, iv)));
        // key null / empty
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", null, iv)));
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", new byte[0], iv)));
        // iv null / empty
        assertThrows(WopSdkException.class,
                () -> DekPayload.encode(new DekPayload("AES256-GCM", k, null)));
        assertThrows(WopSdkException.class,
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
        // null / 空
        assertThrows(WopSdkException.class, () -> DekPayload.decode(null));
        assertThrows(WopSdkException.class, () -> DekPayload.decode(""));
        // 段数错误（2 段 / 4 段）
        assertThrows(WopSdkException.class, () -> DekPayload.decode("a$b"));
        assertThrows(WopSdkException.class, () -> DekPayload.decode("a$b$c$d"));
        // alg 段空白
        assertThrows(WopSdkException.class, () -> DekPayload.decode("$AAAA$BBBB"));
        // key/iv 段非法 base64url（catch 分支）
        assertThrows(WopSdkException.class,
                () -> DekPayload.decode("AES256-GCM$!!!$AAAA"));
        assertThrows(WopSdkException.class,
                () -> DekPayload.decode("AES256-GCM$AAAA$==="));
    }

    // ==================== WopClient.buildRequest 空数组 body 路径 ====================

    @Test
    void buildRequestEmptyByteArrayBodyIsNoBody() {
        WopClient client = testClient();
        // L0 + 空数组：hasBody=false → wireBody=null → digest 缺席（与 null body 同语义）
        RequestDraft draft = client.buildRequest("POST", "/gateway/test", new byte[0], SecurityLevel.L0);
        assertNull(draft.wireBody());
        assertNull(draft.headers().get("x-wop-content-digest"));
        // L2 + 空数组：拒绝（L2 需要非空 body）
        assertThrows(WopSdkException.class,
                () -> client.buildRequest("POST", "/gateway/test", new byte[0], SecurityLevel.L2));
    }
}

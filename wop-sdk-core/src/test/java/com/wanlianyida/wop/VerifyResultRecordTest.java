package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * VerifyResult（record 生成方法 + 对外语义）与 Builder/请求边界闭合。
 */
class VerifyResultRecordTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    @Test
    void recordEqualsHashCodeToString() {
        byte[] plain = Codec.utf8("p");
        VerifyResult a = VerifyResult.ok(plain);
        VerifyResult b = VerifyResult.ok(plain);   // record 数组字段浅比较：同引用相等
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertEquals("VerifyResult[ok]", a.toString());
        assertArrayEquals(plain, a.plaintext());
        assertEquals("p", a.plaintextAsUtf8());

        VerifyResult failNoDetail = VerifyResult.fail(VerifyResult.Reason.SIGNATURE_FAILED, null);
        VerifyResult failWithDetail = VerifyResult.fail(VerifyResult.Reason.MISSING_HEADER, "x-wop-nonce");
        assertFalse(a.equals(failNoDetail));
        assertEquals("签名验证失败", failNoDetail.message());
        assertEquals("签名验证失败", failNoDetail.toString().replace("VerifyResult[fail: ", "").replace("]", ""));
        assertEquals("签名的请求头缺失: x-wop-nonce", failWithDetail.message());
        assertEquals("VerifyResult[fail: 签名的请求头缺失: x-wop-nonce]", failWithDetail.toString());
        assertFalse(a.equals(null));
        assertFalse(a.equals("str"));
        assertNull(failNoDetail.plaintextAsUtf8());
        assertNull(a.message());
    }

    @Test
    void messageOfOkIsNullAndReasonEnumCoversAll() {
        assertNull(VerifyResult.ok(new byte[0]).message());
        assertNull(VerifyResult.ok(new byte[0]).reason());
        // Reason 全枚举 message 非空（对外语义冻结）
        for (VerifyResult.Reason reason : VerifyResult.Reason.values()) {
            assertFalse(reason.message().isBlank());
        }
    }

    @Test
    void builderEdgeBranches() {
        // blank 字段全部拒绝
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey(" ").build());
        assertThrows(WopSdkException.class, () -> WopClient.builder().appKey("a").suite(" ").build());
        WopClient.Builder half = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(" ").platformPublicKey(RSA_PUB);
        assertThrows(WopSdkException.class, half::build);
        WopClient.Builder noPlatform = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(" ");
        assertThrows(WopSdkException.class, noPlatform::build);
        // expiredSeconds 边界
        WopClient.Builder badExpired = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).expiredSeconds(0);
        assertThrows(WopSdkException.class, badExpired::build);
        assertNotNullBuild(WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).expiredSeconds(60));
    }

    private void assertNotNullBuild(WopClient.Builder builder) {
        assertTrue(builder.build() != null);
    }

    @Test
    void buildRequestEdgeBranches() {
        WopClient client = WopClient.builder().appKey("a").suite("WOP-RSA3072-SHA256")
                .merchantPrivateKey(RSA_PRIV).platformPublicKey(RSA_PUB).build();
        // null method / null path
        assertThrows(WopSdkException.class, () -> client.buildRequest(null, "/p", null, SecurityLevel.L0));
        assertThrows(WopSdkException.class, () -> client.buildRequest("POST", null, null, SecurityLevel.L0));
        // 空 body 数组按无 body 处理（digest 缺席）
        RequestDraft draft = client.buildRequest("GET", "/p", new byte[0], SecurityLevel.L0);
        assertFalse(draft.headers().containsKey("x-wop-content-digest"));
        assertNull(draft.wireBody());
        // 空白签头响应拒绝
        assertEquals(VerifyResult.Reason.MISSING_SIGN_HEADER,
                client.verifyResponse(Map.of("x-wop-sign", "  "), Codec.utf8("{}"), "/p").reason());
        // 空 digest 头值（有 body）
        assertEquals(VerifyResult.Reason.MISSING_DIGEST_HEADER,
                client.verifyResponse(Map.of("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/a/b",
                        "x-wop-content-digest", " "), Codec.utf8("x"), "/p").reason());
        // L2 但 digest 头为空白串
        assertEquals(VerifyResult.Reason.MISSING_DIGEST_HEADER,
                client.verifyResponse(Map.of("x-wop-sign", "WOP-RSA3072-SHA256 v1/1800/a/b",
                        "x-wop-content-digest", ""), Codec.utf8("x"), "/p").reason());
    }
}

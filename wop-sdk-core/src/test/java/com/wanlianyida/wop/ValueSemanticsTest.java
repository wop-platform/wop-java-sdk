package com.wanlianyida.wop;

import com.wanlianyida.wop.crypto.AlgorithmSuite;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * record→class 改写后的值语义契约（equals/hashCode/toString 按全部字段）：
 * 逐字段矩阵确保每个 Objects.equals 的 true/false 分支均被触达，维持 JaCoCo 100% 门禁。
 * 数组字段按引用比较（record 等价语义），同值断言共用同一数组引用。
 */
class ValueSemanticsTest {

    private static RequestDraft draft() {
        return new RequestDraft("POST", "/p",
                Collections.singletonMap("x-wop-appkey", "a"), new byte[]{1});
    }

    @Test
    void requestDraftValueSemantics() {
        byte[] body = draft().wireBody(); // 数组字段按引用比较：同值断言共享同一引用
        RequestDraft base = new RequestDraft("POST", "/p",
                Collections.singletonMap("x-wop-appkey", "a"), body);
        assertEquals(base, new RequestDraft("POST", "/p",
                Collections.singletonMap("x-wop-appkey", "a"), body));
        assertEquals(base.hashCode(), new RequestDraft("POST", "/p",
                Collections.singletonMap("x-wop-appkey", "a"), body).hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "x");
        assertNotEquals(base, new RequestDraft("GET", "/p",
                Collections.singletonMap("x-wop-appkey", "a"), body));
        assertNotEquals(base, new RequestDraft("POST", "/q",
                Collections.singletonMap("x-wop-appkey", "a"), body));
        assertNotEquals(base, new RequestDraft("POST", "/p",
                Collections.singletonMap("x-wop-appkey", "b"), body));
        assertNotEquals(base, new RequestDraft("POST", "/p",
                Collections.singletonMap("x-wop-appkey", "a"), new byte[]{2}));
        assertTrue(base.toString().contains("POST"));
        assertTrue(base.toString().contains("/p"));
    }

    @Test
    void transportResponseValueSemantics() {
        byte[] body = new byte[]{1, 2};
        TransportResponse base = new TransportResponse(200,
                Collections.singletonMap("x-wop-sign", "s"), body);
        assertEquals(200, base.statusCode());
        assertEquals(base, new TransportResponse(200,
                Collections.singletonMap("x-wop-sign", "s"), body));
        assertEquals(base.hashCode(), new TransportResponse(200,
                Collections.singletonMap("x-wop-sign", "s"), body).hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) 42);
        assertNotEquals(base, new TransportResponse(500,
                Collections.singletonMap("x-wop-sign", "s"), body));
        assertNotEquals(base, new TransportResponse(200,
                Collections.singletonMap("x-wop-sign", "t"), body));
        assertNotEquals(base, new TransportResponse(200,
                Collections.singletonMap("x-wop-sign", "s"), new byte[]{9}));
        assertTrue(base.toString().contains("200"));
        assertTrue(base.toString().contains("x-wop-sign"));
    }

    @Test
    void verifyResultValueSemantics() {
        byte[] plain = new byte[]{7};
        VerifyResult base = new VerifyResult(true, plain,
                VerifyResult.Reason.DECRYPT_FAILED, "d");
        assertEquals(base, new VerifyResult(true, plain,
                VerifyResult.Reason.DECRYPT_FAILED, "d"));
        assertEquals(base.hashCode(), new VerifyResult(true, plain,
                VerifyResult.Reason.DECRYPT_FAILED, "d").hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "v");
        assertNotEquals(base, new VerifyResult(false, plain,
                VerifyResult.Reason.DECRYPT_FAILED, "d"));
        assertNotEquals(base, new VerifyResult(true, new byte[]{8},
                VerifyResult.Reason.DECRYPT_FAILED, "d"));
        assertNotEquals(base, new VerifyResult(true, plain,
                VerifyResult.Reason.DIGEST_MISMATCH, "d"));
        assertNotEquals(base, new VerifyResult(true, plain,
                VerifyResult.Reason.DECRYPT_FAILED, "other"));
        // toString 用对外文案（10.2）而非枚举名；成功形态不含明文
        assertTrue(new VerifyResult(false, null,
                VerifyResult.Reason.DECRYPT_FAILED, null).toString().contains("解密失败"));
        assertTrue(base.toString().contains("ok"));
    }

    @Test
    void configValueSemantics() {
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
        WopClient.Config base = new WopClient.Config("app", suite, "mk", "pk", 1800);
        assertEquals(base, new WopClient.Config("app", suite, "mk", "pk", 1800));
        assertEquals(base.hashCode(), new WopClient.Config("app", suite, "mk", "pk", 1800).hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "cfg");
        assertNotEquals(base, new WopClient.Config("app2", suite, "mk", "pk", 1800));
        assertNotEquals(base, new WopClient.Config("app",
                AlgorithmSuite.parse("WOP-SM2-SM3"), "mk", "pk", 1800));
        assertNotEquals(base, new WopClient.Config("app", suite, "mk2", "pk", 1800));
        assertNotEquals(base, new WopClient.Config("app", suite, "mk", "pk2", 1800));
        assertNotEquals(base, new WopClient.Config("app", suite, "mk", "pk", 3600));
        assertTrue(base.toString().contains("app"));
        assertTrue(base.toString().contains("1800"));
    }
}

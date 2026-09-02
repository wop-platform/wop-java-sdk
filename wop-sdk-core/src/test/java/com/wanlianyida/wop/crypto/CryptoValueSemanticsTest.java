package com.wanlianyida.wop.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * crypto 包 record→class 改写后的值语义契约（equals/hashCode/toString 按全部字段）：
 * 逐字段矩阵触达每个 Objects.equals 的 true/false 分支。数组字段按引用比较（record 等价语义）。
 */
class CryptoValueSemanticsTest {

    @Test
    void contentDigestParsedValueSemantics() {
        ContentDigest.Parsed base = new ContentDigest.Parsed("SHA256", "abcd");
        assertEquals(base, new ContentDigest.Parsed("SHA256", "abcd"));
        assertEquals(base.hashCode(), new ContentDigest.Parsed("SHA256", "abcd").hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "p");
        assertNotEquals(base, new ContentDigest.Parsed("SM3", "abcd"));
        assertNotEquals(base, new ContentDigest.Parsed("SHA256", "ffff"));
        assertTrue(base.toString().contains("SHA256"));
        assertTrue(base.toString().contains("abcd"));
    }

    @Test
    void encryptHeaderParsedValueSemantics() {
        EncryptHeader.Parsed base = new EncryptHeader.Parsed("L2", "dek");
        assertEquals(base, new EncryptHeader.Parsed("L2", "dek"));
        assertEquals(base.hashCode(), new EncryptHeader.Parsed("L2", "dek").hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "h");
        assertNotEquals(base, new EncryptHeader.Parsed("L0", "dek"));
        assertNotEquals(base, new EncryptHeader.Parsed("L2", "other"));
        assertTrue(base.toString().contains("L2"));
    }

    @Test
    void signHeaderParsedValueSemantics() {
        SignHeader.Parsed base = new SignHeader.Parsed("WOP-RSA3072-SHA256", "v1", 1800,
                Arrays.asList("a", "b"), "sig");
        SignHeader.Parsed same = new SignHeader.Parsed("WOP-RSA3072-SHA256", "v1", 1800,
                Arrays.asList("a", "b"), "sig");
        assertEquals(base, same);
        assertEquals(base.hashCode(), same.hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "s");
        assertNotEquals(base, new SignHeader.Parsed("WOP-SM2-SM3", "v1", 1800,
                Arrays.asList("a", "b"), "sig"));
        assertNotEquals(base, new SignHeader.Parsed("WOP-RSA3072-SHA256", "v2", 1800,
                Arrays.asList("a", "b"), "sig"));
        assertNotEquals(base, new SignHeader.Parsed("WOP-RSA3072-SHA256", "v1", 900,
                Arrays.asList("a", "b"), "sig"));
        assertNotEquals(base, new SignHeader.Parsed("WOP-RSA3072-SHA256", "v1", 1800,
                Arrays.asList("a"), "sig"));
        assertNotEquals(base, new SignHeader.Parsed("WOP-RSA3072-SHA256", "v1", 1800,
                Arrays.asList("a", "b"), "sig2"));
        assertTrue(base.toString().contains("v1"));
        assertTrue(base.toString().contains("sig"));
    }

    @Test
    void dekPayloadValueSemantics() {
        byte[] key = new byte[]{1};
        byte[] iv = new byte[]{2};
        DekPayload base = new DekPayload("RSA-OAEP-3072", key, iv);
        assertEquals(base, new DekPayload("RSA-OAEP-3072", key, iv));
        assertEquals(base.hashCode(), new DekPayload("RSA-OAEP-3072", key, iv).hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) Collections.emptyMap());
        assertNotEquals(base, new DekPayload("SM2", key, iv));
        assertNotEquals(base, new DekPayload("RSA-OAEP-3072", new byte[]{9}, iv));
        assertNotEquals(base, new DekPayload("RSA-OAEP-3072", key, new byte[]{9}));
        assertTrue(base.toString().contains("RSA-OAEP-3072"));
        assertTrue(base.toString().contains("hidden"));
    }
}

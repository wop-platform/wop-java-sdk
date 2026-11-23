package com.wanlianyida.wop;

import com.wanlianyida.wop.config.HttpClientSettings;
import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.ContentDigest;
import com.wanlianyida.wop.crypto.DekPayload;
import com.wanlianyida.wop.crypto.EncryptHeader;
import com.wanlianyida.wop.crypto.SignHeader;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * PIT r2 补测：值对象 hashCode 与默认值（PrimitiveReturns / EmptyObjectReturnVals 变异）。
 * 断言「不同字段值 → 不同哈希」，恒定返回 0 或空对象即红。
 */
class MutationKillValueHashTest {

    private static Map<String, String> headers(String name, String value) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put(name, value);
        return map;
    }

    @Test
    void requestDraftHashDependsOnFields() {
        RequestDraft a = new RequestDraft("GET", "/gateway/a", headers("k", "v1"), null);
        RequestDraft b = new RequestDraft("POST", "/gateway/b", headers("k", "v2"), new byte[]{1});
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void transportCallHashDependsOnFields() {
        TransportCall a = TransportCall.of("https://a.example.com/gateway", 1000, 2000);
        TransportCall b = TransportCall.of("https://b.example.com/gateway", 1001, 2001);
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void transportResponseHashDependsOnFields() {
        TransportResponse a = new TransportResponse(200, headers("x", "1"), new byte[]{1});
        TransportResponse b = new TransportResponse(500, headers("x", "2"), new byte[]{2});
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void verifyResultHashDependsOnFields() {
        VerifyResult a = new VerifyResult(true, new byte[]{1}, VerifyResult.Reason.SIGNATURE_FAILED, "detail-a");
        VerifyResult b = new VerifyResult(false, new byte[]{2}, VerifyResult.Reason.DIGEST_MISMATCH, "detail-b");
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void clientConfigHashDependsOnFields() {
        AlgorithmSuite suite = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
        WopClient.Config a = new WopClient.Config("app_001", suite, "priv-a", "pub-a", 1800L);
        WopClient.Config b = new WopClient.Config("app_002", suite, "priv-b", "pub-b", 1801L);
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void requestOptionsHashDependsOnFields() {
        WopRequestOptions a = WopRequestOptions.builder().appKey("app_001").build();
        WopRequestOptions b = WopRequestOptions.builder().appKey("app_002").build();
        assertNotEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void requestOptionsResolvedSubMchIdIsNullWhenUnset() {
        assertNull(WopRequestOptions.none().resolvedSubMchId());
        assertNull(WopRequestOptions.builder().build().resolvedSubMchId());
        assertEquals("mch_001", WopRequestOptions.builder().subMchId("mch_001").build().resolvedSubMchId());
    }

    @Test
    void httpClientSettingsHashDependsOnFields() {
        assertNotEquals(new HttpClientSettings(1000, 2000, 0).hashCode(),
                new HttpClientSettings(1000, 2001, 0).hashCode());
    }

    @Test
    void contentDigestParsedHashDependsOnFields() {
        assertNotEquals(new ContentDigest.Parsed("SHA256", "aa").hashCode(),
                new ContentDigest.Parsed("SM3", "bb").hashCode());
    }

    @Test
    void dekPayloadHashDependsOnFields() {
        assertNotEquals(new DekPayload("AES-256-GCM", new byte[]{1}, new byte[]{2}).hashCode(),
                new DekPayload("AES-256-GCM", new byte[]{3}, new byte[]{4}).hashCode());
    }

    @Test
    void encryptHeaderParsedHashDependsOnFields() {
        assertNotEquals(new EncryptHeader.Parsed("L1", "dek-a").hashCode(),
                new EncryptHeader.Parsed("L2", "dek-b").hashCode());
    }

    @Test
    void signHeaderParsedHashDependsOnFields() {
        SignHeader.Parsed a = new SignHeader.Parsed("WOP-RSA3072-SHA256", "I1", 1800L, Arrays.asList("a"), "sig-a");
        SignHeader.Parsed b = new SignHeader.Parsed("WOP-RSA3072-SHA256", "I1", 1801L, Arrays.asList("a"), "sig-b");
        assertNotEquals(a.hashCode(), b.hashCode());
    }
}

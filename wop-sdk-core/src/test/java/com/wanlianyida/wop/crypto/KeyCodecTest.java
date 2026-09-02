package com.wanlianyida.wop.crypto;
import com.wanlianyida.wop.WopSdkException;
import org.junit.jupiter.api.Test;


import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KeyCodec（D12 密钥分发契约）测试：PEM/Base64 双形态、SM2 04‖X‖Y/d 标量、
 * RSA 长度与套件一致、非法输入明确拒绝。
 */
class KeyCodecTest {

    private static final AlgorithmSuite RSA3072 = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite RSA4096 = AlgorithmSuite.parse("WOP-RSA4096-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    @Test
    void parsesRsaSpkiPublicBase64() {
        RSAPublicKey key = assertInstanceOf(RSAPublicKey.class,
                KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072));
        assertEquals(3072, key.getModulus().bitLength());
    }

    @Test
    void parsesRsaSpkiPublicPem() {
        String b64 = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();
        String pem = "-----BEGIN PUBLIC KEY-----\n" + chunk(b64) + "\n-----END PUBLIC KEY-----\n";
        assertEquals(3072, ((RSAPublicKey) KeyCodec.parsePublicKey(pem, RSA3072)).getModulus().bitLength());
    }

    @Test
    void parsesRsaPkcs8PrivateBase64AndPem() {
        String b64 = TestVectors.keys("rsa4096").path("privatePkcs8B64").asText();
        assertEquals(4096, ((RSAPrivateKey) KeyCodec.parsePrivateKey(b64, RSA4096)).getModulus().bitLength());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + chunk(b64) + "\n-----END PRIVATE KEY-----\n";
        assertNotNull(KeyCodec.parsePrivateKey(pem, RSA4096));
    }

    @Test
    void parsesSm2RawPointPublicAndScalarPrivate() {
        // D12：公钥 04||X||Y 65B、私钥 d 32B（Base64）
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        assertNotNull(pub);
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        assertNotNull(priv);
        // 缓存命中返回同一实例（D7）
        assertTrue(pub == KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2));
    }

    @Test
    void parsesSm2SpkiPublicAndPkcs8Private() {
        // 由 04||X||Y 构造 SPKI、由 d 构造 PKCS#8 后回喂（形态互认）
        byte[] point = Base64.getDecoder().decode(TestVectors.keys("sm2").path("publicPointB64").asText());
        PublicKey spkiPub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        // SPKI 形态：经策略转换守卫后再喂公钥编码
        String spkiB64 = Base64.getEncoder().encodeToString(spkiPub.getEncoded());
        assertNotNull(KeyCodec.parsePublicKey(spkiB64, SM2));

        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        String pkcs8B64 = Base64.getEncoder().encodeToString(priv.getEncoded());
        assertNotNull(KeyCodec.parsePrivateKey(pkcs8B64, SM2));
        assertEquals(point.length, 65);
    }

    @Test
    void rejectsRsaLengthMismatchWithSuite() {
        // 4096 密钥喂 3072 套件 → 明确拒绝（支持类）
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePublicKey(TestVectors.keys("rsa4096").path("publicSpkiB64").asText(), RSA3072));
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA4096));
    }

    @Test
    void rejectsBlankAndGarbageKeys() {
        assertThrows(WopSdkException.class, () -> KeyCodec.parsePublicKey(null, RSA3072));
        assertThrows(WopSdkException.class, () -> KeyCodec.parsePrivateKey("  ", RSA3072));
        assertThrows(WopSdkException.class, () -> KeyCodec.parsePublicKey("!!!not-base64!!!", RSA3072));
        assertThrows(WopSdkException.class, () -> KeyCodec.parsePrivateKey("AAAA", SM2));
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePublicKey(Base64.getEncoder().encodeToString(new byte[40]), SM2));
    }

    @Test
    void rejectsCrossFamilyKeyMaterial() {
        // RSA 密钥喂 SM2 套件 / SM2 密钥喂 RSA 套件 → 拒绝
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), SM2));
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), RSA3072));
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), RSA3072));
    }

    @Test
    void rejectsInvalidSm2PointAndScalar() {
        // 非曲线上点 / d 越界
        byte[] bogusPoint = new byte[65];
        bogusPoint[0] = 0x04;
        bogusPoint[64] = 0x01;
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePublicKey(Base64.getEncoder().encodeToString(bogusPoint), SM2));
        byte[] d = new byte[32];
        d[31] = 0x01; // d = 1 合法；改 n 越界用全 FF（> n）
        byte[] over = new byte[32];
        java.util.Arrays.fill(over, (byte) 0xFF);
        assertThrows(WopSdkException.class, () ->
                KeyCodec.parsePrivateKey(Base64.getEncoder().encodeToString(over), SM2));
        assertEquals(1, new java.math.BigInteger(1, d).intValueExact());
    }

    private static String chunk(String base64) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < base64.length(); i += 64) {
            sb.append(base64, i, Math.min(base64.length(), i + 64)).append('\n');
        }
        return sb.toString().replaceAll("\\s+$", "");
    }
}

package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.InteropConformanceTest;
import com.wanlianyida.wop.crypto.strategies.KeyEncryptStrategy;
import com.wanlianyida.wop.crypto.strategies.RsaOaepKeyEncryptStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm2KeyEncryptStrategy;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A1/A2 密钥加密向量：OAEP 显式双 SHA-256 解包 + MGF1-SHA-1 陷阱拒绝 + roundtrip；
 * SM2 C1C3C2 固定 k 密文解包 + C1C2C3 顺序负向量。
 */
class KeyEncryptVectorTest {

    private static final AlgorithmSuite RSA3072 = AlgorithmSuite.parse("WOP-RSA3072-SHA256");
    private static final AlgorithmSuite RSA4096 = AlgorithmSuite.parse("WOP-RSA4096-SHA256");
    private static final AlgorithmSuite SM2 = AlgorithmSuite.parse("WOP-SM2-SM3");

    @Test
    void oaep3072UnwrapMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("keyEncrypt", "oaep3072-unwrap");
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        byte[] cipher = Codec.b64UrlDecode(vector.path("cipherB64u").asText());
        byte[] plain = RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(cipher, priv);
        // 字节级：解包明文 = DEK 载荷
        assertEquals(vector.path("expectedPlaintext").asText(), new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    void oaep4096UnwrapMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("keyEncrypt", "oaep4096-unwrap");
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa4096").path("privatePkcs8B64").asText(), RSA4096);
        byte[] plain = RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(Codec.b64UrlDecode(vector.path("cipherB64u").asText()), priv);
        assertEquals(vector.path("expectedPlaintext").asText(), new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    void oaepMgf1Sha1TrapRejected() {
        // F2 钉子：以错误 MGF1（SHA-1）包装的密文，用规格参数（双 SHA-256）解包必须失败
        JsonNode vector = TestVectors.firstById("keyEncrypt", "oaep3072-mgf1sha1-trap");
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        byte[] trap = Codec.b64UrlDecode(vector.path("cipherB64u").asText());
        assertThrows(CryptoException.class, () -> RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(trap, priv));
    }

    @Test
    void oaepRoundtrip() {
        // OAEP 加密随机化无法字节钉；产出密文经规格参数解包须等于明文
        JsonNode vector = TestVectors.firstById("keyEncrypt", "oaep3072-wrap-roundtrip");
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        byte[] payload = Codec.utf8(vector.path("plaintext").asText());
        byte[] wrapped = RsaOaepKeyEncryptStrategy.INSTANCE.encrypt(payload, pub);
        assertArrayEquals(payload, RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(wrapped, priv));
    }

    @Test
    void oaepTamperRejected() {
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa4096").path("publicSpkiB64").asText(), RSA4096);
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa4096").path("privatePkcs8B64").asText(), RSA4096);
        byte[] wrapped = RsaOaepKeyEncryptStrategy.INSTANCE.encrypt(Codec.utf8("dek"), pub);
        wrapped[20] ^= 0x01;
        byte[] finalWrapped = wrapped;
        assertThrows(CryptoException.class, () -> RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(finalWrapped, priv));
    }

    @Test
    void sm2FixedKCipherDecryptsToPlaintext() {
        JsonNode vector = TestVectors.firstById("keyEncrypt", "sm2-encrypt-fixedk");
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        byte[] cipher = Codec.b64UrlDecode(vector.path("cipherB64u").asText());
        // C1C3C2 裸拼接：C1 = 04||X||Y 65B 开头
        assertEquals(0x04, cipher[0]);
        assertEquals(65 + 32 + Codec.utf8(vector.path("plaintext").asText()).length, cipher.length);
        byte[] plain = Sm2KeyEncryptStrategy.INSTANCE.decrypt(cipher, priv);
        assertEquals(vector.path("plaintext").asText(), new String(plain, StandardCharsets.UTF_8));
    }

    @Test
    void sm2C1c2c3OrderRejected() {
        // D9 钉子：旧国标 C1C2C3 顺序密文，按 C1C3C2 解密必须失败
        JsonNode vector = TestVectors.firstById("keyEncrypt", "sm2-encrypt-c1c2c3-mismatch");
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        byte[] cipher = Codec.b64UrlDecode(vector.path("cipherB64u").asText());
        assertThrows(CryptoException.class, () -> Sm2KeyEncryptStrategy.INSTANCE.decrypt(cipher, priv));
    }

    @Test
    void sm2EncryptRoundtrip() {
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("sm2").path("publicPointB64").asText(), SM2);
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("sm2").path("privateDB64").asText(), SM2);
        byte[] payload = Codec.utf8("SM4-GCM$" + TestVectors.input("sm4KeyB64u") + "$" + TestVectors.input("sm4IvB64u"));
        byte[] wrapped = Sm2KeyEncryptStrategy.INSTANCE.encrypt(payload, pub);
        assertEquals(0x04, wrapped[0]);
        assertArrayEquals(payload, Sm2KeyEncryptStrategy.INSTANCE.decrypt(wrapped, priv));
    }

    @Test
    void suiteRoutesKeyEncryptStrategy() {
        assertEquals("RSA-OAEP(SHA-256/MGF1-SHA-256)",
                AlgorithmSuite.parse("WOP-RSA3072-SHA256").keyEncrypt().algorithmName());
        assertEquals("SM2", AlgorithmSuite.parse("WOP-SM2-SM3").keyEncrypt().algorithmName());
    }

    @Test
    void nonSm2KeyRejectedBySm2Strategy() {
        // 非 SM2 密钥喂 SM2 策略 → CryptoException（I5 合规边界）
        PrivateKey rsaPriv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        PublicKey rsaPub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        assertThrows(CryptoException.class,
                () -> Sm2KeyEncryptStrategy.INSTANCE.decrypt(new byte[100], rsaPriv));
        assertThrows(CryptoException.class,
                () -> Sm2KeyEncryptStrategy.INSTANCE.encrypt(new byte[10], rsaPub));
    }

    @Test
    void injectedRandomWrapUnwrapRoundtrip() {
        // interop 确定性钩子：注入源包装的密文可正常解包；同流两次包装字节一致（OAEP seed 取自流）
        PrivateKey priv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa3072").path("privatePkcs8B64").asText(), RSA3072);
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        byte[] stream = new byte[96];
        for (int i = 0; i < stream.length; i++) {
            stream[i] = (byte) (i * 3 + 1);
        }
        byte[] payload = Codec.utf8("AES-256-GCM$aaaa$bbbb");
        byte[] wrapped = RsaOaepKeyEncryptStrategy.INSTANCE.encrypt(payload, pub,
                new InteropConformanceTest.StreamRandom(stream));
        byte[] wrapped2 = RsaOaepKeyEncryptStrategy.INSTANCE.encrypt(payload, pub,
                new InteropConformanceTest.StreamRandom(stream));
        assertArrayEquals(wrapped, wrapped2, "同流两次 OAEP 包装应字节一致");
        assertArrayEquals(payload, RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(wrapped, priv));
    }

    @Test
    void spiDefaultInjectFallbackDelegatesToTwoArg() {
        // SPI 默认退路：未覆写注入入口的策略回退 2-arg
        KeyEncryptStrategy fallback = new KeyEncryptStrategy() {
            @Override public byte[] encrypt(byte[] plainKey, PublicKey publicKey) { return plainKey.clone(); }
            @Override public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) { return cipherText; }
            @Override public String algorithmName() { return "stub"; }
        };
        PublicKey pub = KeyCodec.parsePublicKey(TestVectors.keys("rsa3072").path("publicSpkiB64").asText(), RSA3072);
        byte[] out = fallback.encrypt(Codec.utf8("k"), pub, null);
        assertArrayEquals(Codec.utf8("k"), out);
    }

    @Test
    void wrongKeyCannotUnwrap() {
        // 3072 密钥对的密文用 4096 私钥解包必失败（长度即不匹配）
        JsonNode vector = TestVectors.firstById("keyEncrypt", "oaep3072-unwrap");
        PrivateKey wrongPriv = KeyCodec.parsePrivateKey(TestVectors.keys("rsa4096").path("privatePkcs8B64").asText(), RSA4096);
        byte[] cipher = Codec.b64UrlDecode(vector.path("cipherB64u").asText());
        byte[] truncated = Arrays.copyOf(cipher, 384);
        assertThrows(CryptoException.class, () -> RsaOaepKeyEncryptStrategy.INSTANCE.decrypt(truncated, wrongPriv));
    }
}

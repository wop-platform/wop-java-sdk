package com.wanlianyida.wop.crypto.strategies;
import com.fasterxml.jackson.databind.JsonNode;
import com.wanlianyida.wop.crypto.CryptoException;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.InteropConformanceTest;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A1 报文加密正向量 + A2 负向量：AES-256-GCM / SM4-GCM 固定 key/IV 字节级断言
 * （位于 strategies 包以访问向量专用固定 IV 入口）。
 */
class MessageEncryptVectorTest {

    @Test
    void aes256GcmMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("messageEncrypt", "aesgcm-encrypt");
        Aes256GcmStrategy strategy = Aes256GcmStrategy.INSTANCE;
        assertEquals("AES-256-GCM", strategy.algorithmName());
        assertEquals(32, strategy.keyLength());
        assertEquals(12, strategy.ivLength());

        byte[] key = Codec.b64UrlDecode(vector.path("keyB64u").asText());
        byte[] iv = Codec.b64UrlDecode(vector.path("ivB64u").asText());
        byte[] plain = Codec.b64UrlDecode(vector.path("plaintextB64u").asText());
        byte[] expected = Codec.b64UrlDecode(vector.path("cipherTagB64u").asText());

        // 字节级：ciphertext||tag 尾拼（F4），tag 128bit
        assertEquals(plain.length + 16, expected.length);
        assertArrayEquals(expected, strategy.encryptForVector(plain, key, iv).cipher());
        // 解密回环（同向量）
        assertArrayEquals(plain, strategy.decrypt(expected, iv, key));
    }

    @Test
    void sm4GcmMatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("messageEncrypt", "sm4gcm-encrypt");
        Sm4GcmStrategy strategy = Sm4GcmStrategy.INSTANCE;
        assertEquals("SM4-GCM", strategy.algorithmName());
        assertEquals(16, strategy.keyLength());
        assertEquals(12, strategy.ivLength());

        byte[] key = Codec.b64UrlDecode(vector.path("keyB64u").asText());
        byte[] iv = Codec.b64UrlDecode(vector.path("ivB64u").asText());
        byte[] plain = Codec.b64UrlDecode(vector.path("plaintextB64u").asText());
        byte[] expected = Codec.b64UrlDecode(vector.path("cipherTagB64u").asText());

        assertArrayEquals(expected, strategy.encryptForVector(plain, key, iv).cipher());
        assertArrayEquals(plain, strategy.decrypt(expected, iv, key));
    }

    @Test
    void gcmTamperRejected() {
        // A2 负向量：tag/密文篡改必须拒绝（AEAD）
        JsonNode vector = TestVectors.firstById("messageEncrypt", "aesgcm-encrypt");
        byte[] key = Codec.b64UrlDecode(vector.path("keyB64u").asText());
        byte[] iv = Codec.b64UrlDecode(vector.path("ivB64u").asText());
        byte[] plain = Codec.b64UrlDecode(vector.path("plaintextB64u").asText());

        byte[] cipher = Aes256GcmStrategy.INSTANCE.encrypt(plain, key).cipher();
        cipher[cipher.length - 1] ^= 0x01;
        assertThrows(Exception.class, () -> Aes256GcmStrategy.INSTANCE.decrypt(cipher, iv, key));

        byte[] sm4Key = Codec.b64UrlDecode(TestVectors.input("sm4KeyB64u"));
        byte[] sm4Iv = Codec.b64UrlDecode(TestVectors.input("sm4IvB64u"));
        byte[] sm4Cipher = Sm4GcmStrategy.INSTANCE.encrypt(plain, sm4Key).cipher();
        sm4Cipher[0] ^= 0x01;
        assertThrows(Exception.class, () -> Sm4GcmStrategy.INSTANCE.decrypt(sm4Cipher, sm4Iv, sm4Key));
    }

    @Test
    void gcmWrongKeyRejected() {
        JsonNode vector = TestVectors.firstById("messageEncrypt", "aesgcm-encrypt");
        byte[] key = Codec.b64UrlDecode(vector.path("keyB64u").asText());
        byte[] plain = Codec.b64UrlDecode(vector.path("plaintextB64u").asText());
        CipherResult result = Aes256GcmStrategy.INSTANCE.encrypt(plain, key);
        byte[] wrongKey = new byte[32];
        wrongKey[0] = 0x7F;
        assertThrows(Exception.class, () -> Aes256GcmStrategy.INSTANCE.decrypt(result.cipher(), result.iv(), wrongKey));
    }

    @Test
    void encryptGeneratesFreshIvEachCall() {
        // I4 结构性断言：同一密钥下两次加密 IV 必不相同（CSPRNG，出站 IV 生成点唯一）
        byte[] key = Codec.b64UrlDecode(TestVectors.input("aesKeyB64u"));
        byte[] plain = Codec.utf8("iv uniqueness");
        CipherResult a = Aes256GcmStrategy.INSTANCE.encrypt(plain, key);
        CipherResult b = Aes256GcmStrategy.INSTANCE.encrypt(plain, key);
        assertNotEquals(Codec.hexLower(a.iv()), Codec.hexLower(b.iv()));
        assertTrue(a.iv().length == 12 && b.iv().length == 12);

        byte[] sm4Key = Codec.b64UrlDecode(TestVectors.input("sm4KeyB64u"));
        CipherResult c = Sm4GcmStrategy.INSTANCE.encrypt(plain, sm4Key);
        CipherResult d = Sm4GcmStrategy.INSTANCE.encrypt(plain, sm4Key);
        assertNotEquals(Codec.hexLower(c.iv()), Codec.hexLower(d.iv()));
    }

    @Test
    void injectedRandomDrivesIvDeterministically() {
        // interop 确定性钩子：同流两次加密产出相同 IV/密文（IV 仍由策略生成，I4 生成点不变）
        byte[] key = new byte[32];
        byte[] plain = Codec.utf8("deterministic");
        byte[] stream = new byte[64];
        for (int i = 0; i < stream.length; i++) {
            stream[i] = (byte) i;
        }
        CipherResult a = Aes256GcmStrategy.INSTANCE.encrypt(plain, key, new InteropConformanceTest.StreamRandom(stream));
        CipherResult b = Aes256GcmStrategy.INSTANCE.encrypt(plain, key, new InteropConformanceTest.StreamRandom(stream));
        assertArrayEquals(a.iv(), b.iv());
        assertArrayEquals(a.cipher(), b.cipher());

        byte[] sm4Key = new byte[16];
        CipherResult c = Sm4GcmStrategy.INSTANCE.encrypt(plain, sm4Key, new InteropConformanceTest.StreamRandom(stream));
        CipherResult d = Sm4GcmStrategy.INSTANCE.encrypt(plain, sm4Key, new InteropConformanceTest.StreamRandom(stream));
        assertArrayEquals(c.iv(), d.iv());
        assertArrayEquals(c.cipher(), d.cipher());
    }

    @Test
    void spiDefaultInjectFallbackDelegatesToTwoArg() {
        // SPI 默认退路：未覆写注入入口的策略回退 2-arg 自管随机
        MessageEncryptStrategy fallback = new MessageEncryptStrategy() {
            @Override public CipherResult encrypt(byte[] plain, byte[] key) {
                return new CipherResult(plain.clone(), new byte[12]);
            }
            @Override public byte[] decrypt(byte[] cipher, byte[] iv, byte[] key) { return cipher; }
            @Override public String algorithmName() { return "stub"; }
            @Override public int keyLength() { return 0; }
            @Override public int ivLength() { return 0; }
        };
        CipherResult viaDefault = fallback.encrypt(Codec.utf8("x"), new byte[0],
                new java.security.SecureRandom());
        assertArrayEquals(Codec.utf8("x"), viaDefault.cipher());
    }

    @Test
    void keyLengthEnforced() {
        byte[] plain = Codec.utf8("x");
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.encrypt(plain, new byte[16]));
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.encrypt(plain, new byte[32]));
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.decrypt(plain, new byte[12], new byte[16]));
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.decrypt(plain, new byte[12], new byte[32]));
        assertThrows(CryptoException.class, () -> Aes256GcmStrategy.INSTANCE.encrypt(plain, null));
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.encrypt(plain, null));
    }

    @Test
    void ivLengthEnforced() {
        byte[] key16 = Codec.b64UrlDecode(TestVectors.input("sm4KeyB64u"));
        byte[] plain = Codec.utf8("x");
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.decrypt(plain, new byte[11], key16));
        assertThrows(CryptoException.class, () -> Sm4GcmStrategy.INSTANCE.decrypt(plain, null, key16));
        assertThrows(CryptoException.class,
                () -> Sm4GcmStrategy.INSTANCE.encryptForVector(plain, key16, new byte[11]));
    }
}

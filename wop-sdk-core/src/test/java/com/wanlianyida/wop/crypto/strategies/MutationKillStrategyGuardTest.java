package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PIT r2 补测：加解密策略的入参守卫与签名定长转换。
 * 守卫被删后底层 Cipher 仍会抛异常，故必须断言具体消息；{@code to32} 为私有静态，反射直取。
 */
class MutationKillStrategyGuardTest {

    private static final byte[] PLAIN = "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] KEY32 = new byte[32];
    private static final byte[] KEY16 = new byte[16];
    private static final byte[] IV12 = new byte[12];
    private static final byte[] IV11 = new byte[11];

    private static String messageOf(Throwable error) {
        return error.getMessage() == null ? "" : error.getMessage();
    }

    // ==================== Aes256GcmStrategy ====================

    @Test
    void aesEncryptForVectorRejectsBadIv() {
        CryptoException error = assertThrows(CryptoException.class,
                () -> Aes256GcmStrategy.INSTANCE.encryptForVector(PLAIN, KEY32, IV11));
        assertTrue(messageOf(error).contains("IV 须为 12 字节"), messageOf(error));
    }

    @Test
    void aesDecryptRejectsBadKey() {
        CryptoException error = assertThrows(CryptoException.class,
                () -> Aes256GcmStrategy.INSTANCE.decrypt(PLAIN, IV12, KEY16));
        assertTrue(messageOf(error).contains("AES-256 密钥须为 32 字节"), messageOf(error));
    }

    @Test
    void aesDecryptRejectsBadIv() {
        CryptoException error = assertThrows(CryptoException.class,
                () -> Aes256GcmStrategy.INSTANCE.decrypt(PLAIN, IV11, KEY32));
        assertTrue(messageOf(error).contains("IV 须为 12 字节"), messageOf(error));
    }

    // ==================== Sm4GcmStrategy ====================

    @Test
    void sm4EncryptForVectorRejectsBadKey() {
        CryptoException error = assertThrows(CryptoException.class,
                () -> Sm4GcmStrategy.INSTANCE.encryptForVector(PLAIN, new byte[15], IV12));
        assertTrue(messageOf(error).contains("SM4 密钥须为 16 字节"), messageOf(error));
    }

    @Test
    void sm4DecryptRejectsBadKey() {
        CryptoException error = assertThrows(CryptoException.class,
                () -> Sm4GcmStrategy.INSTANCE.decrypt(PLAIN, IV12, new byte[15]));
        assertTrue(messageOf(error).contains("SM4 密钥须为 16 字节"), messageOf(error));
    }

    @Test
    void sm4DecryptRejectsBadIv() {
        CryptoException error = assertThrows(CryptoException.class,
                () -> Sm4GcmStrategy.INSTANCE.decrypt(PLAIN, IV11, KEY16));
        assertTrue(messageOf(error).contains("IV 须为 12 字节"), messageOf(error));
    }

    // ==================== CipherResult.hashCode ====================

    @Test
    void cipherResultHashDependsOnFields() {
        // 数组走引用哈希：不同实例即使内容相同哈希也不同，hashCode 恒 0 的变异必被此断言杀死
        int first = new CipherResult(new byte[]{1}, new byte[]{2}).hashCode();
        int second = new CipherResult(new byte[]{3}, new byte[]{4}).hashCode();
        assertNotEquals(first, second);
    }

    // ==================== Sm2SignatureStrategy.to32 ====================

    @Test
    void sm2To32LeftPadsShortValue() throws Exception {
        byte[] out = invokeTo32(BigInteger.valueOf(0x0102L));
        byte[] expected = new byte[32];
        expected[30] = 0x01;
        expected[31] = 0x02;
        assertArrayEquals(expected, out);
    }

    @Test
    void sm2To32TruncatesHighBytesWhenLongerThan32() throws Exception {
        // 2^255 的 toByteArray 为 33 字节 [0x00, 0x80, 0x00×31]（首字节是符号位补零）；
        // 定长转换须取低 32 字节 → [0x80, 0x00×31]，删掉该分支会得到全零
        byte[] out = invokeTo32(BigInteger.ONE.shiftLeft(255));
        byte[] expected = new byte[32];
        expected[0] = (byte) 0x80;
        assertArrayEquals(expected, out);
    }

    private static byte[] invokeTo32(BigInteger value) throws Exception {
        Method method = Sm2SignatureStrategy.class.getDeclaredMethod("to32", BigInteger.class);
        method.setAccessible(true);
        return (byte[]) method.invoke(null, value);
    }
}

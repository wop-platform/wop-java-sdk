package com.wanlianyida.wop.crypto.strategies;

/**
 * ② 报文加密策略（L2 信封对称加解密，crypto spec §4.1）。
 * 密文与 IV 同生同传（{@link CipherResult}），调用方不可能拿错。
 */
public interface MessageEncryptStrategy {

    /** 加密（IV 由策略内唯一生成点产出，密文与 IV 同生同传）。 */
    CipherResult encrypt(byte[] plain, byte[] key);

    /**
     * 指定随机源加密：IV 仍由策略内唯一生成点产出（I4），但字节取自注入源。
     * <p>确定性钩子（interop 联调合同）：实现未覆写时退回自管 CSPRNG 的 {@link #encrypt(byte[], byte[])}。
     */
    default CipherResult encrypt(byte[] plain, byte[] key, java.security.SecureRandom random) {
        return encrypt(plain, key);
    }

    /** 解密。 */
    byte[] decrypt(byte[] cipher, byte[] iv, byte[] key);

    /** 线上算法名。 */
    String algorithmName();

    /** 密钥长度（字节）。 */
    int keyLength();

    /** IV 长度（字节）。 */
    int ivLength();
}

package com.wanlianyida.wop.crypto.strategies;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * ① 签名策略（crypto spec §4.1）：对 canonicalRequest 加签/验签。
 * 契约：数据与签名一律 byte[]；密钥为 JCA Key（解析归 KeyCodec）；
 * userId 为 SM2 签名/验签身份标识（D14），RSA 忽略。
 */
public interface SignatureStrategy {

    /** 对 canonicalRequest 加签（D14：userId 贯通签名身份；RSA 实现忽略）。 */
    byte[] sign(byte[] data, PrivateKey privateKey, byte[] userId);

    /** 验签（D14：userId 贯通签名身份；RSA 实现忽略）。 */
    boolean verify(byte[] data, byte[] signature, PublicKey publicKey, byte[] userId);

    /** 线上算法名。 */
    String algorithmName();
}

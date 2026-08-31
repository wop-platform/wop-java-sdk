package com.wanlianyida.wop.crypto.strategies;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * ① 签名策略（crypto spec §4.1）：对 canonicalRequest 加签/验签。
 * 契约：数据与签名一律 byte[]；密钥为 JCA Key（解析归 KeyCodec）。
 */
public interface SignatureStrategy {

    /** 对 canonicalRequest 加签。 */
    byte[] sign(byte[] data, PrivateKey privateKey);

    /** 验签。 */
    boolean verify(byte[] data, byte[] signature, PublicKey publicKey);

    /** 线上算法名。 */
    String algorithmName();
}

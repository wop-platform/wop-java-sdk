package com.wanlianyida.wop.crypto.strategies;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * ① 签名策略（crypto spec §4.1）：对 canonicalRequest 加签/验签。
 * 契约：数据与签名一律 byte[]；密钥为 JCA Key（解析归 KeyCodec）；
 * userId 为 SM2 签名/验签身份标识（D14），RSA 忽略。
 * <p>
 * 迁移说明（v0.x，2026-09 D14 审计项）：本接口自 v0.1.0 起要求显式 userId——
 * SM2 的 userId 是 ZA 杂凑输入，参与签名语义，不存在安全默认值（原共享
 * 默认常量已删除）。旧版 2/3 参签名已移除且不提供委托重载：default 方法若回退
 * 到默认 userId 会重新引入被 D14 禁止的静默身份，若抛异常则把编译期错误推迟成
 * 运行时陷阱。实现方请直接更新方法签名（RSA 实现忽略 userId），编译失败即
 * 迁移清单。
 */
public interface SignatureStrategy {

    /** 对 canonicalRequest 加签（D14：userId 贯通签名身份；RSA 实现忽略）。 */
    byte[] sign(byte[] data, PrivateKey privateKey, byte[] userId);

    /** 验签（D14：userId 贯通签名身份；RSA 实现忽略）。 */
    boolean verify(byte[] data, byte[] signature, PublicKey publicKey, byte[] userId);

    /** 线上算法名。 */
    String algorithmName();
}

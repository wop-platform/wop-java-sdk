package com.wopplatform.wopsdk.crypto.strategies;

/**
 * ④ 摘要策略（x-wop-content-digest 底层哈希，crypto spec §4.1）。
 */
public interface DigestStrategy {

    byte[] digest(byte[] data);

    String algorithmName();
}

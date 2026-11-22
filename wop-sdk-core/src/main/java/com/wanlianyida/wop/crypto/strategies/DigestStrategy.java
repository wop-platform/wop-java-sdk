package com.wanlianyida.wop.crypto.strategies;

/**
 * ④ 摘要策略（x-wop-content-digest 底层哈希，crypto spec §4.1）。
 */
public interface DigestStrategy {

    /** 对数据计算摘要（x-wop-content-digest 底层哈希）。 */
    byte[] digest(byte[] data);

    /** 线上算法名。 */
    String algorithmName();
}

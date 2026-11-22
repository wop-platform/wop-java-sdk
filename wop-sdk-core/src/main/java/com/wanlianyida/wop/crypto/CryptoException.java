package com.wanlianyida.wop.crypto;

/**
 * 策略执行失败（统一 unchecked，crypto spec §4.1）。
 * <p>
 * 携带维度 + 算法名 + cause；<b>不得</b>把本类消息直接透出给对端（I7 模糊化由调用边界负责映射）。
 */
public class CryptoException extends RuntimeException {

    /** 以维度/算法名/消息构造（消息自动加 {@code [维度/算法]} 前缀）。 */
    public CryptoException(String dimension, String algorithm, String message) {
        super("[" + dimension + "/" + algorithm + "] " + message);
    }

    /** 携带底层原因构造。 */
    public CryptoException(String dimension, String algorithm, String message, Throwable cause) {
        super("[" + dimension + "/" + algorithm + "] " + message, cause);
    }
}

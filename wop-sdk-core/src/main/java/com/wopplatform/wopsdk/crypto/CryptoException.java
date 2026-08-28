package com.wopplatform.wopsdk.crypto;

/**
 * 策略执行失败（统一 unchecked，crypto spec §4.1）。
 * <p>
 * 携带维度 + 算法名 + cause；<b>不得</b>把本类消息直接透出给对端（I7 模糊化由调用边界负责映射）。
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String dimension, String algorithm, String message) {
        super("[" + dimension + "/" + algorithm + "] " + message);
    }

    public CryptoException(String dimension, String algorithm, String message, Throwable cause) {
        super("[" + dimension + "/" + algorithm + "] " + message, cause);
    }
}

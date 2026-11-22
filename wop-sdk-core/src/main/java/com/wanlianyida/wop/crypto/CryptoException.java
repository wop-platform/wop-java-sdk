package com.wanlianyida.wop.crypto;

public class CryptoException extends RuntimeException {

    /** 以维度/算法名/消息构造（消息自动加 {@code [维度/算法]} 前缀）。 */
    public CryptoException(String dimension, String algorithm, String message) {
        super("[" + dimension + "/" + algorithm + "] " + message);
    }

    public CryptoException(String dimension, String algorithm, String message, Throwable cause) {
        super("[" + dimension + "/" + algorithm + "] " + message, cause);
    }
}

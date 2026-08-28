package com.wopplatform.wopsdk;

/**
 * SDK 显式异常：配置错误、协议头格式错误等<b>鉴权前可判定</b>的公开协议知识（10.2 明确/模糊分界原则）。
 * <p>
 * 验签/解密失败不抛本类——走 {@code VerifyResult} 模糊 reason（I7）。
 */
public class WopSdkException extends RuntimeException {

    public WopSdkException(String message) {
        super(message);
    }

    public WopSdkException(String message, Throwable cause) {
        super(message, cause);
    }
}

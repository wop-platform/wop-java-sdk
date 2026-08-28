package com.wopplatform.wopsdk.crypto.strategies;

/**
 * 对称加密结果：密文（含 GCM tag 尾拼，F4）与 IV 同生同传。
 */
public record CipherResult(byte[] cipher, byte[] iv) {
}

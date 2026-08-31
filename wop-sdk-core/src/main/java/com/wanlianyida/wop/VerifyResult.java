package com.wanlianyida.wop;

import java.nio.charset.StandardCharsets;

/**
 * 校验结果（入向统一出口，永不抛异常）。
 * <p>
 * I7 纪律：reason 是对外可见的全部语义——{@link Reason#SIGNATURE_FAILED} 与
 * {@link Reason#DECRYPT_FAILED} 为<b>模糊</b>（不区分 tag 失败/密钥不符等细节）；
 * 解析/完整性/一致性类按 10.2 对外语义明确。
 *
 * @param ok        是否通过
 * @param plaintext 解密后的明文（L2）或原始 body（L0）；失败时为 null
 * @param reason    失败原因（成功为 null）
 * @param detail    明确类错误的补充细节；模糊类恒为 null
 */
public record VerifyResult(boolean ok, byte[] plaintext, Reason reason, String detail) {

    /** 失败原因分类（对外语义，10.2）。 */
    public enum Reason {
        MISSING_SIGN_HEADER("缺少 x-wop-sign 请求头"),
        INVALID_SIGN_HEADER("x-wop-sign 格式错误"),
        UNSUPPORTED_SUITE("不支持的算法组合"),
        SUITE_MISMATCH("响应套件与客户端配置不符"),
        INVALID_ENCRYPT_HEADER("x-wop-encrypt 格式错误"),
        MISSING_SIGNED_HEADER("signedHeaders 声明不完整"),
        MISSING_HEADER("签名的请求头缺失"),
        SIGNATURE_FAILED("签名验证失败"),
        MISSING_DIGEST_HEADER("缺少 x-wop-content-digest"),
        INVALID_DIGEST_HEADER("x-wop-content-digest 格式非法"),
        DIGEST_MISMATCH("摘要不匹配"),
        DEK_ALG_MISMATCH("DEK alg 与套件族不符"),
        INVALID_ENCRYPTED_BODY("L2 密文载体格式非法"),
        DECRYPT_FAILED("解密失败");

        private final String message;

        /** 以对外文案构造（枚举常量唯一定义点）。 */
        Reason(String message) {
            this.message = message;
        }

        /** 枚举的对外文案（I7：模糊类 reason 即全部对外语义）。 */
        public String message() {
            return message;
        }
    }

    /** 成功结果工厂（包内；入向出口只经 ok/fail 构造，保证不可变纪律）。 */
    static VerifyResult ok(byte[] plaintext) {
        return new VerifyResult(true, plaintext, null, null);
    }

    /** 失败结果工厂（包内；模糊类失败 detail 必须传 null）。 */
    static VerifyResult fail(Reason reason, String detail) {
        return new VerifyResult(false, null, reason, detail);
    }

    /** 对外错误文案（模糊类无细节）。 */
    public String message() {
        if (ok || reason == null) {
            return null;
        }
        return detail == null ? reason.message() : reason.message() + ": " + detail;
    }

    /** 简要结果串（成功/失败与文案，不含明文）。 */
    @Override
    public String toString() {
        return ok ? "VerifyResult[ok]"
                : "VerifyResult[fail: " + message() + "]";
    }

    /** 调试输出避免误泄明文；UTF-8 辅助读取。 */
    public String plaintextAsUtf8() {
        return plaintext == null ? null : new String(plaintext, StandardCharsets.UTF_8);
    }
}

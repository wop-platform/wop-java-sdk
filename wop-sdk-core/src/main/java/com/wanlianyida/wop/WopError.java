package com.wanlianyida.wop;

/**
 * 出向可观测错误（§2.2 WopError 契约）。
 *
 * <p>构造器 / {@code buildRequest} 同步 throw、异步 reject 统一形状
 * {@code WopError{category, message}}；{@link Category} 为闭集（小写 ASCII，跨语言恒定），
 * 禁止自造取值。入向校验（verifyResponse / verifyCallback）不抛本错误，
 * 吞并为 {@link VerifyResult}（I7：category 不可观测，防 oracle）。
 */
public class WopError extends RuntimeException {

    /** 错误类别闭集（小写常量名 = 线上 category 串，跨语言恒定）。 */
    public enum Category {
        /** 配置错误：appKey / 密钥材料缺失或非法、securityReq 非法或跨族（F1）。 */
        configuration,
        /** 协议解析错误：header / 信封 / 线上编码格式（D1/D3）。 */
        parse,
        /** 不支持的算法套件。 */
        unsupported,
        /** 完整性校验失败。 */
        integrity,
        /** 一致性校验：dek alg 与套件族不符（I3）。 */
        consistency,
        /** 验签失败。 */
        signature,
        /** 解密失败（DEK 解包 / GCM tag 两路径同文案，防 oracle 区分）。 */
        decrypt
    }

    private final Category category;

    private WopError(Category category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
    }

    /** 错误类别（闭集，小写 ASCII，跨语言恒定）。 */
    public Category category() {
        return category;
    }

    // ============ 明确文案类工厂（message / message+cause 双变体） ============

    public static WopError configuration(String message) {
        return new WopError(Category.configuration, message, null);
    }

    public static WopError configuration(String message, Throwable cause) {
        return new WopError(Category.configuration, message, cause);
    }

    public static WopError parse(String message) {
        return new WopError(Category.parse, message, null);
    }

    public static WopError parse(String message, Throwable cause) {
        return new WopError(Category.parse, message, cause);
    }

    public static WopError unsupported(String message) {
        return new WopError(Category.unsupported, message, null);
    }

    public static WopError unsupported(String message, Throwable cause) {
        return new WopError(Category.unsupported, message, cause);
    }

    public static WopError integrity(String message) {
        return new WopError(Category.integrity, message, null);
    }

    public static WopError integrity(String message, Throwable cause) {
        return new WopError(Category.integrity, message, cause);
    }

    public static WopError consistency(String message) {
        return new WopError(Category.consistency, message, null);
    }

    public static WopError consistency(String message, Throwable cause) {
        return new WopError(Category.consistency, message, cause);
    }

    // ============ 模糊文案类工厂（无参，固定文案防 oracle） ============

    /** 验签失败（I7：固定模糊文案，防 oracle）。 */
    public static WopError signature() {
        return new WopError(Category.signature, "签名验证失败", null);
    }

    /** 解密失败（DEK 解包 / GCM tag 两路径同文案，防 oracle 区分）。 */
    public static WopError decrypt() {
        return new WopError(Category.decrypt, "解密失败", null);
    }
}

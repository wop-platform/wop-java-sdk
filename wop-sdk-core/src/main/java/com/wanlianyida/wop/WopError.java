package com.wanlianyida.wop;

public class WopError extends RuntimeException {

    /** 错误类别闭集（小写常量名 = 线上 category 串，跨语言恒定）。 */
    public enum Category {
        /** 配置错误：appKey / 密钥材料缺失或非法、securityReq 非法或跨族（F1）。 */
        configuration,
        parse,
        unsupported,
        integrity,
        /** 一致性校验：dek alg 与套件族不符（I3）。 */
        consistency,
        signature,
        decrypt
    }

    private final Category category;

    private WopError(Category category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
    }

    public Category category() {
        return category;
    }


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


    public static WopError signature() {
        return new WopError(Category.signature, "签名验证失败", null);
    }

    public static WopError decrypt() {
        return new WopError(Category.decrypt, "解密失败", null);
    }
}

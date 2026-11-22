package com.wanlianyida.wop.crypto;

/**
 * 套件解析/支持类错误（F1，crypto spec §2.4/§10.2）：
 * <ul>
 *   <li>{@link Kind#PARSE}：空值/格式/前缀 → 对外语义<b>明确</b></li>
 *   <li>{@link Kind#UNSUPPORTED}：算法不在列表、跨族组合 → 对外语义<b>明确</b></li>
 * </ul>
 */
public class WopSuiteException extends RuntimeException {

    public enum Kind { PARSE, UNSUPPORTED }

    private final Kind kind;

    /** 以错误类别构造。 */
    public WopSuiteException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    /** 错误类别（PARSE/UNSUPPORTED，均属对外明确）。 */
    public Kind kind() {
        return kind;
    }
}

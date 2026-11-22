package com.wanlianyida.wop.crypto;

public class WopSuiteException extends RuntimeException {

    public enum Kind { PARSE, UNSUPPORTED }

    private final Kind kind;

    public WopSuiteException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    /** 错误类别（PARSE/UNSUPPORTED，均属对外明确）。 */
    public Kind kind() {
        return kind;
    }
}

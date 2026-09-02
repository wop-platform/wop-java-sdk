package com.wanlianyida.wop;

/** 测试源专用文本工具（Java 8 无 String.repeat）。 */
public final class TestText {

    private TestText() {
    }

    /** 等价 String.repeat(n)：n ≤ 0 返回空串。 */
    public static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * Math.max(n, 0));
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}

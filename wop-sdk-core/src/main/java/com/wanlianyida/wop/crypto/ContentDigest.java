package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopSdkException;

/**
 * F4 x-wop-content-digest（D2 全语义）：
 * <ul>
 *   <li>构造：值 = 套件标签 + <b>恰好一个</b>半角空格 + 小写 hex；摘要对象 = 线上原始报文字节
 *       （L2 时即密文载体）；无 body（GET/空体）→ header <b>缺席</b>，不定义"空串摘要"中间态</li>
 *   <li>解析（严格，多余空白拒绝而非容忍）：标签与套件族强耦合（I5 跨族拒绝），
 *       hex 段恰 64 位小写十六进制</li>
 * </ul>
 */
public final class ContentDigest {

    /** 解析结果：标签 + 64 位小写 hex。 */
    public record Parsed(String label, String hex) {
    }

    private ContentDigest() {
    }

    /** 有 body 必产；无 body（null/空数组）返回 null（缺席）。 */
    public static String build(AlgorithmSuite suite, byte[] wireBody) {
        if (wireBody == null || wireBody.length == 0) {
            return null;
        }
        return suite.digestLabel() + " " + Codec.hexLower(suite.digest().digest(wireBody));
    }

    /** 严格解析：标签 = 套件期望标签（I5），恰一空格，64 位小写 hex；violation 抛明确异常。 */
    public static Parsed parse(String headerValue, AlgorithmSuite suite) {
        if (headerValue == null || headerValue.isEmpty()) {
            throw new WopSdkException("x-wop-content-digest 为空");
        }
        int space = headerValue.indexOf(' ');
        if (space < 0) {
            throw new WopSdkException("x-wop-content-digest 缺少算法标签与 hex 的空格分隔: '" + headerValue + "'");
        }
        if (space != headerValue.lastIndexOf(' ')) {
            throw new WopSdkException("x-wop-content-digest 必须恰好一个空格（D2）: '" + headerValue + "'");
        }
        String label = headerValue.substring(0, space);
        String hex = headerValue.substring(space + 1);
        if (!label.equals(suite.digestLabel())) {
            throw new WopSdkException("x-wop-content-digest 标签 '" + label + "' 与套件族不符（期望 "
                    + suite.digestLabel() + "，跨族拒绝 I5）");
        }
        if (!Codec.isLowerHex64(hex)) {
            throw new WopSdkException("x-wop-content-digest hex 段须为 64 位小写十六进制（D2/F5）: '" + hex + "'");
        }
        return new Parsed(label, hex);
    }
}

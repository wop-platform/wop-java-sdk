package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** 配置专用极简 JSON 解析器（K8/K21）：忽略未知顶层字段；检测重复键；支持一层嵌套 httpClient。 */
final class ConfigJsonParser {

    private static final long DEFAULT_EXPIRED_SECONDS = 1800L;

    private final String json;
    private int pos;

    private ConfigJsonParser(String json) {
        this.json = json;
    }

    static WopSdkConfig parse(String json) {
        if (json == null) {
            throw WopError.configuration("配置文件 JSON 解析失败: 空内容");
        }
        String trimmed = stripBom(json.trim());
        if (trimmed.isEmpty()) {
            throw WopError.configuration("配置文件 JSON 解析失败: 空文件");
        }
        ConfigJsonParser parser = new ConfigJsonParser(trimmed);
        WopSdkConfig config = parser.parseRoot();
        parser.ensureConsumed();
        return config;
    }

    private static String stripBom(String text) {
        return text.startsWith("\uFEFF") ? text.substring(1) : text;
    }

    private WopSdkConfig parseRoot() {
        expect('{');
        String appKey = null;
        String suite = null;
        String merchantPrivateKey = null;
        String platformPublicKey = null;
        String serverRoot = null;
        List<String> backupServerRoots = new ArrayList<>();
        Long expiredSeconds = null;
        HttpClientSettings httpClient = null;
        Set<String> seen = new HashSet<>();
        while (!tryConsume('}')) {
            String key = readString();
            requireDuplicateFree(seen, key);
            expect(':');
            switch (key) {
                case "appKey":
                    appKey = readString();
                    break;
                case "suite":
                    suite = readString();
                    break;
                case "merchantPrivateKey":
                    merchantPrivateKey = readString();
                    break;
                case "platformPublicKey":
                    platformPublicKey = readString();
                    break;
                case "serverRoot":
                    serverRoot = readString();
                    break;
                case "backupServerRoots":
                    backupServerRoots = readStringArray();
                    break;
                case "expiredSeconds":
                    expiredSeconds = readLong("expiredSeconds");
                    break;
                case "httpClient":
                    httpClient = readHttpClient();
                    break;
                default:
                    skipValue();
            }
            requireCommaOrClose();
        }
        HttpClientSettings defaults = HttpClientSettings.defaults();
        WopSdkConfig raw = new WopSdkConfig(
                appKey == null ? "" : appKey,
                suite == null ? "" : suite,
                merchantPrivateKey == null ? "" : merchantPrivateKey,
                platformPublicKey == null ? "" : platformPublicKey,
                serverRoot == null ? "" : serverRoot,
                backupServerRoots,
                expiredSeconds == null ? DEFAULT_EXPIRED_SECONDS : expiredSeconds,
                httpClient == null ? defaults : httpClient,
                null);
        return ConfigValidator.validateAndNormalize(raw);
    }

    private HttpClientSettings readHttpClient() {
        expect('{');
        Integer connect = null;
        Integer read = null;
        Integer maxRetry = null;
        Set<String> seen = new HashSet<>();
        while (!tryConsume('}')) {
            String key = readString();
            requireDuplicateFree(seen, key);
            expect(':');
            switch (key) {
                case "connectTimeout":
                    connect = readPositiveInt("connectTimeout");
                    break;
                case "readTimeout":
                    read = readPositiveInt("readTimeout");
                    break;
                case "maxRetryCount":
                    maxRetry = readNonNegativeInt("maxRetryCount");
                    break;
                default:
                    skipValue();
            }
            requireCommaOrClose();
        }
        HttpClientSettings defaults = HttpClientSettings.defaults();
        return new HttpClientSettings(
                connect == null ? defaults.connectTimeout() : connect,
                read == null ? defaults.readTimeout() : read,
                maxRetry == null ? defaults.maxRetryCount() : maxRetry);
    }

    private List<String> readStringArray() {
        expect('[');
        List<String> values = new ArrayList<>();
        while (!tryConsume(']')) {
            values.add(readString());
            requireCommaOrClose();
        }
        return values;
    }

    private void requireDuplicateFree(Set<String> seen, String key) {
        if (seen.contains(key)) {
            throw WopError.configuration("配置字段 " + key + " 重复: " + key);
        }
        seen.add(key);
    }

    private String readString() {
        skipWhitespace();
        if (pos >= json.length() || json.charAt(pos) != '"') {
            throw syntax("期望字符串");
        }
        pos++;
        StringBuilder out = new StringBuilder();
        while (pos < json.length()) {
            char c = json.charAt(pos++);
            if (c == '"') {
                return out.toString();
            }
            if (c == '\\') {
                if (pos >= json.length()) {
                    throw syntax("字符串转义不完整");
                }
                char esc = json.charAt(pos++);
                switch (esc) {
                    case '"':
                    case '\\':
                    case '/':
                        out.append(esc);
                        break;
                    case 'b':
                        out.append('\b');
                        break;
                    case 'f':
                        out.append('\f');
                        break;
                    case 'n':
                        out.append('\n');
                        break;
                    case 'r':
                        out.append('\r');
                        break;
                    case 't':
                        out.append('\t');
                        break;
                    case 'u':
                        out.append(readUnicode());
                        break;
                    default:
                        throw syntax("非法转义 \\" + esc);
                }
            } else {
                out.append(c);
            }
        }
        throw syntax("字符串未闭合");
    }

    private char readUnicode() {
        if (pos + 4 > json.length()) {
            throw syntax("\\u 转义不完整");
        }
        int code = 0;
        for (int i = 0; i < 4; i++) {
            char h = json.charAt(pos++);
            code <<= 4;
            if (h >= '0' && h <= '9') {
                code += h - '0';
            } else if (h >= 'a' && h <= 'f') {
                code += h - 'a' + 10;
            } else if (h >= 'A' && h <= 'F') {
                code += h - 'A' + 10;
            } else {
                throw syntax("\\u 转义非法");
            }
        }
        return (char) code;
    }

    private long readLong(String fieldName) {
        return readLong(fieldName, true);
    }

    private long readLong(String fieldName, boolean positiveOnly) {
        skipWhitespace();
        int start = pos;
        if (pos < json.length() && json.charAt(pos) == '-') {
            pos++;
        }
        while (pos < json.length() && Character.isDigit(json.charAt(pos))) {
            pos++;
        }
        if (start == pos || (pos == start + 1 && json.charAt(start) == '-')) {
            throw syntax("期望数字");
        }
        String num = json.substring(start, pos);
        if (num.indexOf('e') >= 0 || num.indexOf('E') >= 0
                || num.indexOf('.') >= 0) {
            throw WopError.configuration("配置字段 " + fieldName + " 类型非法: " + num);
        }
        try {
            long value = Long.parseLong(num);
            if (positiveOnly && value <= 0) {
                throw WopError.configuration("配置字段 " + fieldName + " 类型非法: " + num);
            }
            if (!positiveOnly && value < 0) {
                throw WopError.configuration("配置字段 " + fieldName + " 类型非法: " + num);
            }
            return value;
        } catch (NumberFormatException e) {
            throw WopError.configuration("配置字段 " + fieldName + " 类型非法: " + num, e);
        }
    }

    private int readPositiveInt(String fieldName) {
        long value = readLong(fieldName, true);
        if (value > Integer.MAX_VALUE) {
            throw WopError.configuration("配置字段 httpClient 类型非法: 数值越界");
        }
        return (int) value;
    }

    private int readNonNegativeInt(String fieldName) {
        long value = readLong(fieldName, false);
        if (value > Integer.MAX_VALUE) {
            throw WopError.configuration("配置字段 httpClient 类型非法: 数值越界");
        }
        return (int) value;
    }

    private void skipValue() {
        skipWhitespace();
        if (pos >= json.length()) {
            throw syntax("意外结束");
        }
        char c = json.charAt(pos);
        if (c == '"') {
            readString();
        } else if (c == '{') {
            skipObject();
        } else if (c == '[') {
            skipArray();
        } else if (c == 't' || c == 'f' || c == 'n') {
            skipLiteral();
        } else {
            while (pos < json.length()) {
                char ch = json.charAt(pos);
                if (ch == ',' || ch == ']' || ch == '}') {
                    break;
                }
                pos++;
            }
        }
    }

    private void skipObject() {
        expect('{');
        while (!tryConsume('}')) {
            readString();
            expect(':');
            skipValue();
            requireCommaOrClose();
        }
    }

    private void skipArray() {
        expect('[');
        while (!tryConsume(']')) {
            skipValue();
            requireCommaOrClose();
        }
    }

    private void skipLiteral() {
        int start = pos;
        while (pos < json.length() && Character.isLetter(json.charAt(pos))) {
            pos++;
        }
        String literal = json.substring(start, pos).toLowerCase(Locale.ROOT);
        if ("nan".equals(literal) || literal.contains("infinity")) {
            throw WopError.configuration("配置字段 类型非法: NaN/Infinity");
        }
    }

    private void expect(char ch) {
        skipWhitespace();
        if (pos >= json.length() || json.charAt(pos) != ch) {
            throw syntax("期望 '" + ch + "'");
        }
        pos++;
    }

    private boolean tryConsume(char ch) {
        skipWhitespace();
        if (pos < json.length() && json.charAt(pos) == ch) {
            pos++;
            return true;
        }
        return false;
    }

    /** 成员之间必须有逗号，或已到对象/数组结束符。 */
    private void requireCommaOrClose() {
        skipWhitespace();
        if (pos < json.length() && (json.charAt(pos) == '}' || json.charAt(pos) == ']')) {
            return;
        }
        expect(',');
    }

    /** parseRoot 后须消费完输入，拒绝尾随垃圾字符。 */
    private void ensureConsumed() {
        skipWhitespace();
        if (pos < json.length()) {
            throw syntax("JSON 根对象后存在多余内容");
        }
    }

    private void skipWhitespace() {
        while (pos < json.length() && Character.isWhitespace(json.charAt(pos))) {
            pos++;
        }
    }

    private WopError syntax(String detail) {
        return WopError.configuration("配置文件 JSON 解析失败: " + detail);
    }
}

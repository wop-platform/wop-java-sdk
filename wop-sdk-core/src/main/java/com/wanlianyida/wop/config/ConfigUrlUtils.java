package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;

import java.net.URI;
import java.net.URISyntaxException;

/** §7.7 path 语法与网关 URL 校验（K20/K23）。 */
public final class ConfigUrlUtils {

    private ConfigUrlUtils() {
    }

    /** K20：HTTPS 绝对 URL，拒绝 query/fragment，加载时 trim 尾部 /。 */
    public static String validateGatewayUrl(String value, String fieldName) {
        if (value == null || value.trim().isEmpty()) {
            throw WopError.configuration(fieldName + " 不是合法 URL: " + value);
        }
        String trimmed = value.trim();
        URI parsed;
        try {
            parsed = new URI(trimmed);
        } catch (URISyntaxException e) {
            throw WopError.configuration(fieldName + " 不是合法 URL: " + trimmed, e);
        }
        if (parsed.getScheme() == null || !"https".equalsIgnoreCase(parsed.getScheme())) {
            throw WopError.configuration(fieldName + " 须为 HTTPS 绝对 URL: " + trimmed);
        }
        if (parsed.getQuery() != null || parsed.getFragment() != null) {
            throw WopError.configuration(fieldName + " 不得含 query 或 fragment: " + trimmed);
        }
        if (parsed.getHost() == null || parsed.getHost().isEmpty()) {
            throw WopError.configuration(fieldName + " 不是合法 URL: " + trimmed);
        }
        StringBuilder normalized = new StringBuilder("https://");
        normalized.append(parsed.getHost().toLowerCase(java.util.Locale.ROOT));
        if (parsed.getPort() > 0) {
            normalized.append(':').append(parsed.getPort());
        }
        String path = parsed.getPath();
        if (path != null) {
            normalized.append(path);
        }
        String result = normalized.toString();
        if (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

    /** §7.7 API path 语法校验。 */
    public static void validateApiPath(String path) {
        if (path == null || path.trim().isEmpty()) {
            throw WopError.configuration("请求路径为空");
        }
        if (!path.startsWith("/")) {
            throw WopError.configuration("path 须以 / 开头: " + path);
        }
        if (path.startsWith("//")) {
            throw WopError.configuration("path 不得 // 开头: " + path);
        }
        if (path.indexOf('?') >= 0 || path.indexOf('#') >= 0) {
            throw WopError.configuration("path 不得含 query 或 fragment: " + path);
        }
        String lower = path.toLowerCase(java.util.Locale.ROOT);
        if (lower.startsWith("http:") || lower.startsWith("https:")) {
            throw WopError.configuration("path 不得为绝对 URL: " + path);
        }
    }

    /** §7.7 字符串拼接 serverRoot + path（K23）。 */
    public static String joinUrl(String serverRoot, String path) {
        validateApiPath(path);
        String root = serverRoot.endsWith("/") ? serverRoot.substring(0, serverRoot.length() - 1) : serverRoot;
        String trimmedPath = path.startsWith("/") ? path.substring(1) : path;
        return root + '/' + trimmedPath;
    }
}

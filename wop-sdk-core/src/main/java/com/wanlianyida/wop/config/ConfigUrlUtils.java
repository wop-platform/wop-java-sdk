package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;

import java.net.URI;
import java.net.URISyntaxException;

public final class ConfigUrlUtils {

    private ConfigUrlUtils() {
    }

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
        if (parsed.getUserInfo() != null && !parsed.getUserInfo().isEmpty()) {
            throw WopError.configuration(fieldName + " 不得含 user-info: " + trimmed);
        }
        if (parsed.getHost() == null) {
            throw WopError.configuration(fieldName + " 不是合法 URL: " + trimmed);
        }
        StringBuilder normalized = new StringBuilder("https://");
        normalized.append(parsed.getHost().toLowerCase(java.util.Locale.ROOT));
        if (parsed.getPort() > 0) {
            normalized.append(':').append(parsed.getPort());
        }
        normalized.append(parsed.getPath());
        String result = normalized.toString();
        if (result.endsWith("/")) {
            result = result.substring(0, result.length() - 1);
        }
        return result;
    }

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
    }

    public static String joinUrl(String serverRoot, String path) {
        validateApiPath(path);
        String root = serverRoot.endsWith("/") ? serverRoot.substring(0, serverRoot.length() - 1) : serverRoot;
        return root + '/' + path.substring(1);
    }
}

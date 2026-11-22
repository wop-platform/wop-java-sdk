package com.wanlianyida.wop.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;

public final class TestVectors {

    private static final JsonNode ROOT = load();

    private TestVectors() {
    }

    private static JsonNode load() {
        try (InputStream in = TestVectors.class.getResourceAsStream("/crypto-vectors.json")) {
            if (in == null) {
                throw new IllegalStateException("classpath 缺少 crypto-vectors.json（构建期拉取未完成：检查网络与 pom 的 wopSpecsRef 钉版）");
            }
            return new ObjectMapper().readTree(in);
        } catch (Exception e) {
            throw new IllegalStateException("crypto-vectors.json 解析失败", e);
        }
    }

    public static JsonNode root() {
        return ROOT;
    }

    public static JsonNode firstById(String array, String id) {
        for (JsonNode node : ROOT.withArray(array)) {
            if (id.equals(node.path("id").asText())) {
                return node;
            }
        }
        throw new IllegalStateException("向量缺失: " + array + "/" + id);
    }

    public static String formatRuleValue(String id) {
        return firstById("formatRules", id).path("value").asText();
    }

    public static String input(String name) {
        return ROOT.path("inputs").path(name).asText();
    }

    public static JsonNode keys(String name) {
        return ROOT.path("keys").path(name);
    }
}

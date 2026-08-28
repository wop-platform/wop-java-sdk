package com.wopplatform.wopsdk.crypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;

/**
 * 黄金向量装载（docs/crypto-vectors.json 真源副本，经 vectors/ 进入测试 classpath）。
 * 仅测试代码使用，禁止生产代码引用。
 */
public final class TestVectors {

    private static final JsonNode ROOT = load();

    private TestVectors() {
    }

    private static JsonNode load() {
        try (InputStream in = TestVectors.class.getResourceAsStream("/crypto-vectors.json")) {
            if (in == null) {
                throw new IllegalStateException("classpath 缺少 crypto-vectors.json（真源副本应位于 vectors/）");
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

    /** formatRules 向量按 id 取值。 */
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

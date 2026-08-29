package com.wanlianyida.wop;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.Codec;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * interop conformance 消费端（协议编排跨仓一致性合同，wop-specs/interop/v1）。
 * <p>
 * fixture 为真源字节副本（classpath /interop-cases.json，禁手改；sha256 哨兵钉死），
 * 与黄金向量（crypto-vectors.json）同源密钥材料。合同条款：
 * <ul>
 *   <li>build 方向：同 input（固定 timestamp/nonce/随机流）必须复现同 draft——
 *       byte-exact 全量；deterministic-fields 按 opaque 剥离密钥参与段后比对</li>
 *   <li>verify 方向：positive 断言通过且明文一致；negative 断言错误分类逐条对账
 *       （本仓 {@link VerifyResult.Reason} → canonical class 显式映射见
 *       {@link #canonicalClassOf}）</li>
 *   <li>随机流消费顺序：[16B nonce 池（nonce 已由 fixture 提供可忽略）][CEK][12B IV][k…]</li>
 * </ul>
 */
public class InteropConformanceTest {

    /** 真源 sha256（wop-specs/interop/v1/interop-cases.json）；升级样本集须同步此哨兵。 */
    private static final String FIXTURE_SHA256 =
            "3030e98fa6174f1ca905f35d7742ac9471141945dde66f29f01021d51a555f7a";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** 已知样本 id 全集（双向哨兵：fixture 漂移/未登记新增用例即失败）。 */
    private static final Set<String> KNOWN_IDS = Set.of(
            "build:WOP-RSA3072-SHA256:L0", "build:WOP-RSA3072-SHA256:L2",
            "build:WOP-RSA4096-SHA256:L0", "build:WOP-RSA4096-SHA256:L2",
            "build:WOP-SM2-SM3:L0", "build:WOP-SM2-SM3:L2",
            "p07", "p08", "p09", "p10", "p11", "p12", "p13",
            "n01-encrypted-char-damage", "n02-wire-tampered-after-signing",
            "n03-digest-tag-cross-family", "n04-dek-alg-cross-family",
            "n05-dek-c1c2c3-order", "n06-signature-b64-padding",
            "n07-signature-63b", "n08-signature-65b",
            "n09-digest-missing", "n10-digest-not-signed",
            "n11-suite-mismatch", "n12-envelope-missing-field",
            "n13-dek-key-length", "n14-missing-signed-header",
            "n15-digest-without-body", "n16-replay-cross-path");

    // ==================== fixture 完整性哨兵 ====================

    private static byte[] fixtureBytes() {
        try (InputStream in = InteropConformanceTest.class.getResourceAsStream("/interop-cases.json")) {
            assertNotNull(in, "classpath 缺少 interop-cases.json（真源副本应位于 src/test/resources）");
            return in.readAllBytes();
        } catch (Exception e) {
            throw new IllegalStateException("interop-cases.json 读取失败", e);
        }
    }

    private static JsonNode fixture() {
        try {
            return MAPPER.readTree(fixtureBytes());
        } catch (Exception e) {
            throw new IllegalStateException("interop-cases.json 解析失败", e);
        }
    }

    @Test
    void fixtureIntegritySentinels() throws Exception {
        byte[] raw = fixtureBytes();
        StringBuilder sha = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(raw)) {
            sha.append(String.format("%02x", b));
        }
        assertEquals(FIXTURE_SHA256, sha.toString(), "fixture 与真源 sha256 不一致（样本集升级须六仓同步）");

        JsonNode root = MAPPER.readTree(raw);
        assertEquals("wop-interop-1", root.path("_meta").path("format").asText(), "样本集格式版本");
        JsonNode cases = root.path("cases");
        assertEquals(29, cases.size(), "条数哨兵：样本集应为 29 条");
        assertEquals(cases.size(), root.path("_meta").path("caseCount").asInt(), "caseCount 元数据一致");

        Set<String> seen = new HashSet<>();
        for (JsonNode c : cases) {
            seen.add(c.path("id").asText());
        }
        assertEquals(KNOWN_IDS.size(), seen.size(), "已知 id 哨兵：出现未知 id（fixture 漂移或未登记用例）");
        assertEquals(KNOWN_IDS, seen, "已知 id 哨兵：登记 id 有缺失（fixture 被裁剪）");
    }

    // ==================== 错误分类合同：本仓 Reason → canonical class 显式映射 ====================

    /**
     * 显式映射表（无 default 分支——新增 Reason 未登记映射即编译失败，防止分类合同静默漂移）。
     * 依据 wop-specs/interop/v1 README 错误分类合同与已裁决分歧：
     * n06 签名 b64 非法 → protocol；n13 DEK 载荷畸形（除 alg 跨族）→ decrypt-failed；
     * n10 digest 未入签 → protocol；n09 缺 digest 头归完整性类 digest-mismatch（与 Go 真源对齐）。
     */
    static String canonicalClassOf(VerifyResult.Reason reason) {
        return switch (reason) {
            case SIGNATURE_FAILED -> "verify-failed";                                   // 验签类，模糊（I7）
            case DECRYPT_FAILED -> "decrypt-failed";                                    // 解密类，模糊（I7）
            case DIGEST_MISMATCH, MISSING_DIGEST_HEADER -> "digest-mismatch";           // 完整性类，明确（n02/n09）
            case DEK_ALG_MISMATCH -> "alg-mismatch";                                    // 一致性类，明确（D8/n04）
            case MISSING_SIGN_HEADER, INVALID_SIGN_HEADER, UNSUPPORTED_SUITE, SUITE_MISMATCH,
                 INVALID_ENCRYPT_HEADER, MISSING_SIGNED_HEADER, MISSING_HEADER,
                 INVALID_DIGEST_HEADER, INVALID_ENCRYPTED_BODY -> "protocol";           // 解析/协议结构类，明确
        };
    }

    // ==================== build 方向：同输入复现同 draft ====================

    @Test
    void buildDirectionReproducesDraft() {
        int builds = 0;
        for (JsonNode c : fixture().path("cases")) {
            if (!"build".equals(c.path("kind").asText())) {
                continue;
            }
            builds++;
            String id = c.path("id").asText();
            JsonNode input = c.path("input");
            JsonNode expected = c.path("expected");

            String[] key = keyMaterial(c.path("suite").asText());
            long timestampMs = input.path("timestampMs").asLong();
            WopClient client = new WopClient(new WopClient.Config(
                    input.path("appKey").asText(), AlgorithmSuite.parse(c.path("suite").asText()),
                    key[0], key[1], 1800),
                    () -> timestampMs,
                    () -> input.path("nonce").asText(),
                    new StreamRandom(hexDecode(input.path("randomHex").asText())));
            RequestDraft draft = client.buildRequest(
                    input.path("method").asText(),
                    input.path("path").asText(),
                    Codec.b64UrlDecode(input.path("plaintextB64").asText()),
                    SecurityLevel.valueOf(c.path("level").asText()));

            assertEquals(expected.path("wireBodyB64").asText(), Codec.b64UrlEncode(draft.wireBody()),
                    id + ": wire body 字节不一致");

            Set<String> opaque = new HashSet<>();
            expected.path("opaque").forEach(o -> opaque.add(o.asText()));
            JsonNode expectedHeaders = expected.path("headers");
            assertEquals(expectedHeaders.size(), draft.headers().size(), id + ": 头集合不一致");
            for (Map.Entry<String, JsonNode> want : asIterable(expectedHeaders)) {
                String name = want.getKey().toLowerCase(Locale.ROOT);
                String got = draft.headers().get(name);
                assertNotNull(got, id + ": 缺头 " + want.getKey());
                String wantValue = want.getValue().asText();
                if (opaque.contains("x-wop-sign.signatureSegment") && "x-wop-sign".equals(name)) {
                    got = stripSignatureSegment(got);
                    wantValue = stripSignatureSegment(wantValue);
                }
                if (opaque.contains("x-wop-encrypt.dekValue") && "x-wop-encrypt".equals(name)) {
                    got = stripDekValue(got);
                    wantValue = stripDekValue(wantValue);
                }
                assertEquals(wantValue, got, id + ": 头 " + want.getKey() + " 不一致");
            }
        }
        assertEquals(6, builds, "build 用例数哨兵");
    }

    // ==================== verify 方向：positive 明文一致 + negative 错误分类对账 ====================

    @Test
    void verifyDirectionPositiveAndNegative() {
        int positives = 0;
        int negatives = 0;
        Map<String, WopClient> clients = new LinkedHashMap<>();
        for (JsonNode c : fixture().path("cases")) {
            String kind = c.path("kind").asText();
            if (!kind.startsWith("verify-")) {
                continue;
            }
            String id = c.path("id").asText();
            JsonNode response = c.path("response");
            JsonNode expect = c.path("expect");

            WopClient client = clients.computeIfAbsent(c.path("suite").asText(),
                    suite -> interopClient(suite, response.path("appKey").asText()));
            Map<String, String> headers = new LinkedHashMap<>();
            response.path("headers").fields().forEachRemaining(e -> headers.put(e.getKey(), e.getValue().asText()));
            String verifyPath = c.hasNonNull("verifyPath") ? c.path("verifyPath").asText()
                    : response.path("path").asText();
            VerifyResult result = client.verifyResponse(headers,
                    Codec.b64UrlDecode(response.path("wireBodyB64").asText()), verifyPath);

            if ("verify-positive".equals(kind)) {
                positives++;
                assertTrue(result.ok(), id + ": 应通过（" + result + "）");
                assertArrayEquals(Codec.b64UrlDecode(expect.path("plaintextB64").asText()),
                        result.plaintext(), id + ": 明文不一致");
            } else {
                negatives++;
                assertFalse(result.ok(), id + ": 应拒绝");
                assertEquals(expect.path("errorClass").asText(), canonicalClassOf(result.reason()),
                        id + ": 错误分类不一致（本仓 reason=" + result.reason() + "）");
            }
        }
        assertEquals(7, positives, "verify-positive 条数哨兵");
        assertEquals(16, negatives, "verify-negative 条数哨兵");
    }

    // ==================== 辅助 ====================

    /** 套件 → 黄金向量密钥材料 [priv, pub]（与真源生成器 interopClient 同一映射）。 */
    private static String[] keyMaterial(String suite) {
        JsonNode keys = TestVectors.keys(switch (suite) {
            case "WOP-SM2-SM3" -> "sm2";
            case "WOP-RSA4096-SHA256" -> "rsa4096";
            default -> "rsa3072";
        });
        String priv = keys.has("privatePkcs8B64") ? keys.path("privatePkcs8B64").asText()
                : keys.path("privateDB64").asText();
        String pub = keys.has("publicSpkiB64") ? keys.path("publicSpkiB64").asText()
                : keys.path("publicPointB64").asText();
        return new String[]{priv, pub};
    }

    private static WopClient interopClient(String suite, String appKey) {
        String[] key = keyMaterial(suite);
        return new WopClient(new WopClient.Config(appKey, AlgorithmSuite.parse(suite), key[0], key[1], 1800),
                System::currentTimeMillis, () -> "unused");
    }

    /** 小写 hex → 字节（Codec 仅提供编码方向；测试侧解码）。 */
    private static byte[] hexDecode(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                    | Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return out;
    }

    /**
     * 确定性随机流（合同消费顺序 [CEK][12B IV][wrap 填充随机]；nonce 已由 fixture
     * 提供故 16B nonce 池不消费）；耗尽后填 0x5A 与 Go 消费端 hexReader 同语义。
     */
    public static final class StreamRandom extends SecureRandom {
        private final byte[] stream;
        private int pos;

        public StreamRandom(byte[] stream) {
            this.stream = stream;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = pos < stream.length ? stream[pos++] : 0x5A;
            }
        }
    }

    private static String stripSignatureSegment(String signHeader) {
        int i = signHeader.lastIndexOf('/');
        return i >= 0 ? signHeader.substring(0, i + 1) : signHeader;
    }

    private static String stripDekValue(String encryptHeader) {
        int i = encryptHeader.indexOf("dek=");
        return i >= 0 ? encryptHeader.substring(0, i + 4) : encryptHeader;
    }

    private static Iterable<Map.Entry<String, JsonNode>> asIterable(JsonNode object) {
        return object::fields;
    }
}

package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.crypto.strategies.DigestStrategy;
import com.wanlianyida.wop.crypto.strategies.Sha256DigestStrategy;
import com.wanlianyida.wop.crypto.strategies.Sm3DigestStrategy;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * A1 摘要正向量：黄金向量 digest 段字节级断言（SHA-256 / SM3）。
 */
class DigestStrategyVectorTest {

    @Test
    void sha256MatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("digest", "digest-sha256");
        DigestStrategy strategy = Sha256DigestStrategy.INSTANCE;
        assertEquals("SHA-256", strategy.algorithmName());
        byte[] hash = strategy.digest(vector.path("input").asText().getBytes(StandardCharsets.UTF_8));
        assertEquals(32, hash.length);
        // 字节级：小写 hex 与向量一致
        assertEquals(vector.path("expectedHex").asText(), Codec.hexLower(hash));
    }

    @Test
    void sm3MatchesGoldenVector() {
        JsonNode vector = TestVectors.firstById("digest", "digest-sm3");
        DigestStrategy strategy = Sm3DigestStrategy.INSTANCE;
        assertEquals("SM3", strategy.algorithmName());
        byte[] hash = strategy.digest(vector.path("input").asText().getBytes(StandardCharsets.UTF_8));
        assertEquals(32, hash.length);
        assertEquals(vector.path("expectedHex").asText(), Codec.hexLower(hash));
    }

    @Test
    void suiteRoutesDigestStrategy() {
        assertEquals("SHA-256", AlgorithmSuite.parse("WOP-RSA3072-SHA256").digest().algorithmName());
        assertEquals("SM3", AlgorithmSuite.parse("WOP-SM2-SM3").digest().algorithmName());
    }
}

package com.wanlianyida.wop.crypto.bench;

import com.wanlianyida.wop.crypto.CanonicalRequest;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * trimall / canonicalHeaders 微基准：新实现与旧正则实现在同一 JVM 轮次对照。
 * 复跑步骤与实测数据见 {@code docs/adr/0002-trimall-hand-rolled-fold.md}。
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
@State(Scope.Thread)
public class TrimallBenchmark {

    @Param({"x-wop-timestamp", " 1758900000000 ", "sha-256   4cf7\t9a2e"})
    public String text;

    private Map<String, String> headers;

    @Setup
    public void setUp() {
        headers = new LinkedHashMap<>();
        headers.put("X-Wop-Timestamp", " 1758900000000 ");
        headers.put("x-wop-nonce", "ab c");
        headers.put("X-WOP-CONTENT-DIGEST", "sha-256 4cf7");
        headers.put("X-Wop-App-Key", "app_001");
        headers.put("X-Wop-Security-Req", "WOP-RSA2048-SHA256  v1/1800/a/b");
    }

    @Benchmark
    public String trimallCurrent() {
        return CanonicalRequest.trimall(text);
    }

    @Benchmark
    public String trimallLegacy() {
        return legacyTrimall(text);
    }

    @Benchmark
    public String canonicalHeadersCurrent() {
        return CanonicalRequest.canonicalHeaders(headers);
    }

    @Benchmark
    public String canonicalHeadersLegacy() {
        Map<String, String> sorted = new java.util.TreeMap<>();
        headers.forEach((name, value) ->
                sorted.put(legacyTrimall(name).toLowerCase(java.util.Locale.ROOT), legacyTrimall(value)));
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            if (sb.length() != 0) {
                sb.append('\n');
            }
            sb.append(CanonicalRequest.urlencode(entry.getKey())).append(':')
                    .append(CanonicalRequest.urlencode(entry.getValue()));
        }
        return sb.toString();
    }

    /** 改造前的实现，作为同轮对照基线（勿删：删掉则失去 before/after 可比性）。 */
    private static String legacyTrimall(String text) {
        if (text == null) {
            return "";
        }
        return text.trim().replaceAll("\\s+", " ");
    }
}

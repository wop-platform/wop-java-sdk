package perf.jmh;

import com.wanlianyida.wop.crypto.CanonicalRequest;
import com.wanlianyida.wop.crypto.strategies.Sha256DigestStrategy;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * SDK 请求前处理链候选点微基准：trimall 正则消除、SHA-256 摘要实例复用。
 * <p>
 * 成对方法在同一 fork 内交替采样：一侧是当前生产实现，另一侧是候选改法。
 * 用途是给「要不要改」提供同运行对照读数，本基准不改生产代码。
 *
 * @author perf-sdk
 * @date 2026-11-23
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class SdkRequestPrepBenchmark {

    private static final String HEADER_VALUE = "  x-wop-appkey    AKID6F3A9C2E5B7D1\n x-wop-timestamp\t1234567890 ";

    private static final ThreadLocal<MessageDigest> SHA256 = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    });

    private Map<String, String> headers;
    private byte[] body;

    @Setup
    public void setUp() {
        headers = new LinkedHashMap<>();
        headers.put("x-wop-appkey", "  AKID6F3A9C2E5B7D1   ");
        headers.put("x-wop-timestamp", "\t1234567890 ");
        headers.put("content-type", "application/json");
        body = new byte[1024];
    }

    @Benchmark
    public String trimall_regex() {
        return HEADER_VALUE.trim().replaceAll("\\s+", " ");
    }

    @Benchmark
    public String trimall_manual() {
        return foldWhitespace(HEADER_VALUE);
    }

    @Benchmark
    public String canonicalHeaders_current() {
        return CanonicalRequest.canonicalHeaders(headers);
    }

    @Benchmark
    public byte[] sha256_newInstance() {
        return Sha256DigestStrategy.INSTANCE.digest(body);
    }

    @Benchmark
    public byte[] sha256_threadLocal() {
        MessageDigest md = SHA256.get();
        md.reset();
        return md.digest(body);
    }

    private static String foldWhitespace(String text) {
        if (text == null) {
            return "";
        }
        String trimmed = text.trim();
        int len = trimmed.length();
        int i = 0;
        while (i < len && !isRegexWhitespace(trimmed.charAt(i))) {
            i++;
        }
        if (i == len) {
            return trimmed;
        }
        StringBuilder sb = new StringBuilder(len);
        sb.append(trimmed, 0, i);
        boolean inWhitespace = false;
        for (; i < len; i++) {
            char c = trimmed.charAt(i);
            if (isRegexWhitespace(c)) {
                if (!inWhitespace) {
                    sb.append(' ');
                    inWhitespace = true;
                }
            } else {
                sb.append(c);
                inWhitespace = false;
            }
        }
        return sb.toString();
    }

    private static boolean isRegexWhitespace(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\u000B' || c == '\f' || c == '\r';
    }
}

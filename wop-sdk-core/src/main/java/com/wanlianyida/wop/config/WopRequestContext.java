package com.wanlianyida.wop.config;

import com.wanlianyida.wop.TransportCall;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.WopRequestOptions;
import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.KeyCodec;
import com.wanlianyida.wop.crypto.WopSuiteException;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * 内部请求上下文：全局配置与 {@link WopRequestOptions} 合并后的方向性凭证视图（K24/K25）。
 */
public final class WopRequestContext {

    /** 出向签名/DEK 包装凭证。 */
    public static final class Outbound {

        private final String appKey;
        private final AlgorithmSuite suite;
        private final PrivateKey merchantPrivateKey;
        private final PublicKey platformPublicKey;
        private final long expiredSeconds;

        Outbound(String appKey, AlgorithmSuite suite, PrivateKey merchantPrivateKey,
                 PublicKey platformPublicKey, long expiredSeconds) {
            this.appKey = appKey;
            this.suite = suite;
            this.merchantPrivateKey = merchantPrivateKey;
            this.platformPublicKey = platformPublicKey;
            this.expiredSeconds = expiredSeconds;
        }

        public String appKey() {
            return appKey;
        }

        public AlgorithmSuite suite() {
            return suite;
        }

        public PrivateKey merchantPrivateKey() {
            return merchantPrivateKey;
        }

        public PublicKey platformPublicKey() {
            return platformPublicKey;
        }

        public long expiredSeconds() {
            return expiredSeconds;
        }
    }

    /** 入向验签/DEK 解包凭证（SM2 ZA 仍用平台固定 userId，D15）。 */
    public static final class Inbound {

        private final AlgorithmSuite suite;
        private final PublicKey platformPublicKey;
        private final PrivateKey merchantPrivateKey;

        Inbound(AlgorithmSuite suite, PublicKey platformPublicKey, PrivateKey merchantPrivateKey) {
            this.suite = suite;
            this.platformPublicKey = platformPublicKey;
            this.merchantPrivateKey = merchantPrivateKey;
        }

        public AlgorithmSuite suite() {
            return suite;
        }

        public PublicKey platformPublicKey() {
            return platformPublicKey;
        }

        public PrivateKey merchantPrivateKey() {
            return merchantPrivateKey;
        }
    }

    private final Outbound outbound;
    private final Inbound inbound;
    private final String primaryServerRoot;
    private final List<String> failoverCandidates;
    private final int maxRetryCount;
    private final int connectTimeoutMillis;
    private final int readTimeoutMillis;

    private WopRequestContext(Outbound outbound, Inbound inbound, String primaryServerRoot,
                              List<String> failoverCandidates, int maxRetryCount,
                              Integer connectTimeoutMillis, Integer readTimeoutMillis) {
        this.outbound = outbound;
        this.inbound = inbound;
        this.primaryServerRoot = primaryServerRoot;
        this.failoverCandidates = failoverCandidates;
        this.maxRetryCount = maxRetryCount;
        this.connectTimeoutMillis = connectTimeoutMillis == null ? TransportCall.USE_DEFAULT : connectTimeoutMillis;
        this.readTimeoutMillis = readTimeoutMillis == null ? TransportCall.USE_DEFAULT : readTimeoutMillis;
    }

    /** verifyCallback 凭证覆盖：仅合并凭证字段，忽略 serverRoot/超时（K10）。 */
    public static WopRequestContext resolveInboundOnly(WopSdkConfig global, WopRequestOptions options) {
        return resolve(global, stripTransportFields(options));
    }

    private static WopRequestOptions stripTransportFields(WopRequestOptions options) {
        if (options == null || options == WopRequestOptions.none()) {
            return WopRequestOptions.none();
        }
        return WopRequestOptions.builder()
                .appKey(options.appKey())
                .suite(options.suite())
                .merchantPrivateKey(options.merchantPrivateKey())
                .platformPublicKey(options.platformPublicKey())
                .expiredSeconds(options.expiredSeconds())
                .build();
    }

    /** §6.3 resolve：合并 + 复校验 + 方向性视图。 */
    public static WopRequestContext resolve(WopSdkConfig global, WopRequestOptions options) {
        Objects.requireNonNull(global, "global");
        if (options == null || options == WopRequestOptions.none()) {
            return defaultFor(global);
        }
        String appKey = options.hasAppKey() ? options.appKey().trim() : global.appKey();
        String suiteStr = options.hasSuite() ? options.suite().trim() : global.suite();
        String merchantKey = options.hasMerchantPrivateKey()
                ? options.merchantPrivateKey().trim() : global.merchantPrivateKey();
        String platformKey = options.hasPlatformPublicKey()
                ? options.platformPublicKey().trim() : global.platformPublicKey();
        long expired = options.hasExpiredSeconds() ? options.expiredSeconds() : global.expiredSeconds();

        if (appKey.isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: appKey");
        }
        if (suiteStr.isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: suite");
        }
        if (merchantKey.isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: merchantPrivateKey");
        }
        if (platformKey.isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: platformPublicKey");
        }
        if (expired <= 0) {
            throw WopError.configuration("expiredSeconds 须为正整数");
        }

        AlgorithmSuite suite;
        try {
            suite = AlgorithmSuite.parse(suiteStr);
        } catch (WopSuiteException e) {
            throw WopError.configuration("不支持的算法套件: " + suiteStr, e);
        }
        PrivateKey merchantPrivate;
        PublicKey platformPublic;
        try {
            merchantPrivate = KeyCodec.parsePrivateKey(merchantKey, suite);
            platformPublic = KeyCodec.parsePublicKey(platformKey, suite);
        } catch (RuntimeException e) {
            throw WopError.configuration("密钥解析失败: " + e.getMessage(), e);
        }

        String serverRoot;
        List<String> candidates;
        if (options.hasServerRoot()) {
            serverRoot = ConfigUrlUtils.validateGatewayUrl(options.serverRoot(), "serverRoot");
            candidates = Collections.singletonList(serverRoot);
        } else {
            serverRoot = global.serverRoot();
            candidates = buildFailoverCandidates(global.serverRoot(), global.backupServerRoots());
        }

        Integer connect = options.hasConnectTimeout() ? options.connectTimeout() : global.httpClient().connectTimeout();
        Integer read = options.hasReadTimeout() ? options.readTimeout() : global.httpClient().readTimeout();
        if (connect <= 0 || read <= 0) {
            throw WopError.configuration("配置字段 httpClient 类型非法: 超时须为正整数，maxRetryCount 须非负");
        }

        Outbound outbound = new Outbound(appKey, suite, merchantPrivate, platformPublic, expired);
        Inbound inbound = new Inbound(suite, platformPublic, merchantPrivate);
        return new WopRequestContext(outbound, inbound, serverRoot, candidates,
                global.httpClient().maxRetryCount(), connect, read);
    }

    private static WopRequestContext defaultFor(WopSdkConfig global) {
        AlgorithmSuite suite = AlgorithmSuite.parse(global.suite());
        PrivateKey merchant = KeyCodec.parsePrivateKey(global.merchantPrivateKey(), suite);
        PublicKey platform = KeyCodec.parsePublicKey(global.platformPublicKey(), suite);
        Outbound outbound = new Outbound(global.appKey(), suite, merchant, platform, global.expiredSeconds());
        Inbound inbound = new Inbound(suite, platform, merchant);
        List<String> candidates = buildFailoverCandidates(global.serverRoot(), global.backupServerRoots());
        return new WopRequestContext(outbound, inbound, global.serverRoot(), candidates,
                global.httpClient().maxRetryCount(),
                global.httpClient().connectTimeout(),
                global.httpClient().readTimeout());
    }

    private static List<String> buildFailoverCandidates(String primary, List<String> backups) {
        Set<String> seen = new LinkedHashSet<>();
        List<String> out = new ArrayList<>();
        addCandidate(out, seen, primary);
        for (String backup : backups) {
            addCandidate(out, seen, backup);
        }
        return Collections.unmodifiableList(out);
    }

    private static void addCandidate(List<String> out, Set<String> seen, String root) {
        if (root != null && !root.isEmpty() && seen.add(root)) {
            out.add(root);
        }
    }

    public Outbound outbound() {
        return outbound;
    }

    public Inbound inbound() {
        return inbound;
    }

    public List<String> failoverCandidates() {
        return failoverCandidates;
    }

    public int maxRetryCount() {
        return maxRetryCount;
    }

    /** 当前笔主网关（Failover 首候选）。 */
    public String primaryServerRoot() {
        return primaryServerRoot;
    }

    public TransportCall toTransportCall() {
        return toTransportCall(primaryServerRoot);
    }

    public TransportCall toTransportCall(String serverRoot) {
        return TransportCall.of(serverRoot, connectTimeoutMillis, readTimeoutMillis);
    }

    /** K16：日志/toString 不含明文密钥。 */
    public String toMaskedString() {
        return "WopRequestContext[primaryServerRoot=" + primaryServerRoot
                + ", failoverCandidates=" + failoverCandidates
                + ", maxRetryCount=" + maxRetryCount
                + ", connectTimeoutMillis=" + connectTimeoutMillis
                + ", readTimeoutMillis=" + readTimeoutMillis
                + ", outbound.appKey=" + outbound.appKey()
                + ", outbound.suite=" + outbound.suite().securityReq()
                + ", outbound.merchantPrivateKey=****, outbound.platformPublicKey=****"
                + ", inbound.suite=" + inbound.suite().securityReq()
                + ", inbound.merchantPrivateKey=****, inbound.platformPublicKey=****]";
    }

    @Override
    public String toString() {
        return toMaskedString();
    }
}

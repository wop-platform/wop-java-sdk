package com.wanlianyida.wop.config;

import com.wanlianyida.wop.Transport;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** 不可变配置快照（与 JSON camelCase 字段一一对应，§3）。 */
public final class WopSdkConfig {

    private final String appKey;
    private final String suite;
    private final String merchantPrivateKey;
    private final String platformPublicKey;
    private final String serverRoot;
    private final List<String> backupServerRoots;
    private final long expiredSeconds;
    private final HttpClientSettings httpClient;
    private final Transport transport;

    WopSdkConfig(String appKey, String suite, String merchantPrivateKey, String platformPublicKey,
                 String serverRoot, List<String> backupServerRoots, long expiredSeconds,
                 HttpClientSettings httpClient, Transport transport) {
        this.appKey = appKey;
        this.suite = suite;
        this.merchantPrivateKey = merchantPrivateKey;
        this.platformPublicKey = platformPublicKey;
        this.serverRoot = serverRoot;
        this.backupServerRoots = Collections.unmodifiableList(backupServerRoots);
        this.expiredSeconds = expiredSeconds;
        this.httpClient = httpClient;
        this.transport = transport;
    }

    public String appKey() {
        return appKey;
    }

    public String suite() {
        return suite;
    }

    public String merchantPrivateKey() {
        return merchantPrivateKey;
    }

    public String platformPublicKey() {
        return platformPublicKey;
    }

    public String serverRoot() {
        return serverRoot;
    }

    public List<String> backupServerRoots() {
        return backupServerRoots;
    }

    public long expiredSeconds() {
        return expiredSeconds;
    }

    public HttpClientSettings httpClient() {
        return httpClient;
    }

    /** 可选注入传输；缺省时 execute 走 SPI 发现（K11）。 */
    public Transport transport() {
        return transport;
    }

    /** K16：日志/toString 凭证打码。 */
    public String toMaskedString() {
        return "WopSdkConfig[appKey=" + appKey + ", suite=" + suite
                + ", merchantPrivateKey=****, platformPublicKey=****, serverRoot=" + serverRoot
                + ", backupServerRoots=" + backupServerRoots + ", expiredSeconds=" + expiredSeconds
                + ", httpClient=" + httpClient + ']';
    }

    @Override
    public String toString() {
        return toMaskedString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof WopSdkConfig)) {
            return false;
        }
        WopSdkConfig that = (WopSdkConfig) o;
        return expiredSeconds == that.expiredSeconds
                && Objects.equals(appKey, that.appKey)
                && Objects.equals(suite, that.suite)
                && Objects.equals(merchantPrivateKey, that.merchantPrivateKey)
                && Objects.equals(platformPublicKey, that.platformPublicKey)
                && Objects.equals(serverRoot, that.serverRoot)
                && Objects.equals(backupServerRoots, that.backupServerRoots)
                && Objects.equals(httpClient, that.httpClient)
                && transport == that.transport;
    }

    @Override
    public int hashCode() {
        return Objects.hash(appKey, suite, merchantPrivateKey, platformPublicKey, serverRoot,
                backupServerRoots, expiredSeconds, httpClient, transport);
    }

    /** 程序化构造（K11），build() 执行与 JSON 路径等价的 §3.4 校验。 */
    public static final class Builder {

        private String appKey;
        private String suite;
        private String merchantPrivateKey;
        private String platformPublicKey;
        private String serverRoot;
        private List<String> backupServerRoots = Collections.emptyList();
        private long expiredSeconds = 1800L;
        private HttpClientSettings httpClient = HttpClientSettings.defaults();
        private Transport transport;

        public Builder appKey(String appKey) {
            this.appKey = appKey;
            return this;
        }

        public Builder suite(String suite) {
            this.suite = suite;
            return this;
        }

        public Builder merchantPrivateKey(String merchantPrivateKey) {
            this.merchantPrivateKey = merchantPrivateKey;
            return this;
        }

        public Builder platformPublicKey(String platformPublicKey) {
            this.platformPublicKey = platformPublicKey;
            return this;
        }

        public Builder serverRoot(String serverRoot) {
            this.serverRoot = serverRoot;
            return this;
        }

        public Builder backupServerRoots(List<String> backupServerRoots) {
            this.backupServerRoots = backupServerRoots == null
                    ? Collections.emptyList() : backupServerRoots;
            return this;
        }

        public Builder backupServerRoots(String... backupServerRoots) {
            this.backupServerRoots = backupServerRoots == null
                    ? Collections.emptyList() : Arrays.asList(backupServerRoots);
            return this;
        }

        public Builder expiredSeconds(long expiredSeconds) {
            this.expiredSeconds = expiredSeconds;
            return this;
        }

        public Builder httpClient(HttpClientSettings httpClient) {
            this.httpClient = httpClient == null ? HttpClientSettings.defaults() : httpClient;
            return this;
        }

        public Builder transport(Transport transport) {
            this.transport = transport;
            return this;
        }

        public WopSdkConfig build() {
            WopSdkConfig raw = new WopSdkConfig(
                    appKey == null ? "" : appKey,
                    suite == null ? "" : suite,
                    merchantPrivateKey == null ? "" : merchantPrivateKey,
                    platformPublicKey == null ? "" : platformPublicKey,
                    serverRoot == null ? "" : serverRoot,
                    backupServerRoots,
                    expiredSeconds,
                    httpClient,
                    transport);
            return ConfigValidator.validateAndNormalize(raw);
        }
    }
}

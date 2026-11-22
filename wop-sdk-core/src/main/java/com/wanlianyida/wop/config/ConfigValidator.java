package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.AlgorithmSuite;
import com.wanlianyida.wop.crypto.KeyCodec;
import com.wanlianyida.wop.crypto.WopSuiteException;

import java.util.ArrayList;
import java.util.List;

/** §3.4 语义校验与字段归一化。 */
final class ConfigValidator {

    private ConfigValidator() {
    }

    static WopSdkConfig validateAndNormalize(WopSdkConfig raw) {
        if (raw.appKey() == null || raw.appKey().trim().isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: appKey");
        }
        if (raw.suite() == null || raw.suite().trim().isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: suite");
        }
        if (raw.merchantPrivateKey() == null || raw.merchantPrivateKey().trim().isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: merchantPrivateKey");
        }
        if (raw.platformPublicKey() == null || raw.platformPublicKey().trim().isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: platformPublicKey");
        }
        if (raw.serverRoot() == null || raw.serverRoot().trim().isEmpty()) {
            throw WopError.configuration("配置文件缺少必填项: serverRoot");
        }
        if (raw.expiredSeconds() <= 0) {
            throw WopError.configuration("expiredSeconds 须为正整数");
        }

        AlgorithmSuite suite;
        try {
            suite = AlgorithmSuite.parse(raw.suite().trim());
        } catch (WopSuiteException e) {
            throw WopError.configuration("不支持的算法套件: " + raw.suite(), e);
        }
        try {
            KeyCodec.parsePrivateKey(raw.merchantPrivateKey().trim(), suite);
            KeyCodec.parsePublicKey(raw.platformPublicKey().trim(), suite);
        } catch (RuntimeException e) {
            throw WopError.configuration("密钥解析失败: " + e.getMessage(), e);
        }

        String serverRoot = ConfigUrlUtils.validateGatewayUrl(raw.serverRoot(), "serverRoot");
        List<String> backups = new ArrayList<>();
        for (int i = 0; i < raw.backupServerRoots().size(); i++) {
            backups.add(ConfigUrlUtils.validateGatewayUrl(
                    raw.backupServerRoots().get(i), "backupServerRoots[" + i + "]"));
        }

        HttpClientSettings http = raw.httpClient() == null ? HttpClientSettings.defaults() : raw.httpClient();
        if (http.connectTimeout() <= 0 || http.readTimeout() <= 0 || http.maxRetryCount() < 0) {
            throw WopError.configuration("配置字段 httpClient 类型非法: 超时须为正整数，maxRetryCount 须非负");
        }

        return new WopSdkConfig(
                raw.appKey().trim(),
                raw.suite().trim(),
                raw.merchantPrivateKey().trim(),
                raw.platformPublicKey().trim(),
                serverRoot,
                backups,
                raw.expiredSeconds(),
                http,
                raw.transport());
    }
}

package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;

import java.security.Provider;

/**
 * jdk15on 发行线的 BouncyCastle 版本下限守卫（1.65）。
 * <p>
 * 消费者可能在自己的 pom 中声明更低的 bcprov-jdk15on，并因 Maven 就近优先胜出；
 * 此处 fail-fast 转为明确的配置错误，避免下游抛 {@code NoSuchMethodError}。
 * <p>
 * 独立成包内类而非挂在 {@link BouncyCastleHolder} 上：后者是公共 API 门禁覆盖的类，
 * 任何成员增减都会被 japicmp 记为 break。
 */
final class BouncyCastleVersionGuard {

    /** 最低 BC 版本（1.65 起纳入测试矩阵）。 */
    static final double MIN_VERSION = 1.65;

    /** 工具类禁实例化。 */
    private BouncyCastleVersionGuard() {
    }

    /** 版本守卫：低于 {@link #MIN_VERSION} 明确拒绝。 */
    static Provider requireSupported(Provider provider) {
        requireSupportedVersion(provider.getVersion());
        return provider;
    }

    /** 版本判定（拆出便于单测覆盖两侧分支）。 */
    static void requireSupportedVersion(double version) {
        if (version < MIN_VERSION) {
            throw WopError.configuration("BouncyCastle 版本过低（当前 " + version
                    + "，要求 >= " + MIN_VERSION + "）：请将 bcprov-jdk15on 升级到 1.65 及以上，"
                    + "或改用 jdk18on 发行线");
        }
    }
}

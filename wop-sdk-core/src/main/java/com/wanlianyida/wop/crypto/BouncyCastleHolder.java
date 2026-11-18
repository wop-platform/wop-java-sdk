package com.wanlianyida.wop.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * BouncyCastle Provider 进程级单例（国密 SM2/SM3/SM4 唯一路径，E5）。
 * 直接持有自身实例：Security.addProvider 对同名已注册情形返回 -1 无害，
 * 我们始终使用自建实例，规避对全局注册状态的分支依赖。
 * <p>
 * 版本校验放在 {@link #provider()} 取用时而非静态初始化块：静态初始化抛出的
 * 运行时异常会被 JVM 包装为 {@link ExceptionInInitializerError}，调用方按
 * {@code WopError} catch 不到；取用时校验可让配置错误以原始类型直达调用方。
 * <p>
 * jdk15on 发行线：最低版本 1.65，见 {@link BouncyCastleVersionGuard}。
 */
public final class BouncyCastleHolder {

    private static final Provider PROVIDER = register();

    /** 工具类禁实例化。 */
    private BouncyCastleHolder() {
    }

    /**
     * 已注册的 BC Provider（进程级单例）。
     *
     * @throws com.wanlianyida.wop.WopError BC 版本低于 {@link BouncyCastleVersionGuard#MIN_VERSION}
     */
    public static Provider provider() {
        return BouncyCastleVersionGuard.requireSupported(PROVIDER);
    }

    /** 自建实例注册（同名已注册返回 -1 无害，始终使用自建实例）。 */
    private static Provider register() {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }
}

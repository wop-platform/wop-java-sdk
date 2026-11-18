package com.wanlianyida.wop.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;

/**
 * BouncyCastle Provider 进程级单例（国密 SM2/SM3/SM4 唯一路径，E5）。
 * <p>
 * 不调用 {@code Security.addProvider}：所有 JCA 查找都显式传入 provider 实例，
 * 既避免污染宿主的全局 Provider 表，也保证被版本守卫拒绝的实例不会残留可被
 * 其他组件选中。
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
     * BC Provider 单例（未注册到全局 Provider 表）。
     *
     * @throws com.wanlianyida.wop.WopError BC 版本低于 {@link BouncyCastleVersionGuard#MIN_VERSION}
     */
    public static Provider provider() {
        return BouncyCastleVersionGuard.requireSupported(PROVIDER);
    }

    /** 创建自建实例（仅持有，不注册全局）。 */
    private static Provider register() {
        return new BouncyCastleProvider();
    }
}

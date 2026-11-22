package com.wanlianyida.wop.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * BouncyCastle Provider 进程级单例注册（国密 SM2/SM3/SM4 唯一路径，E5）。
 * 直接持有自身实例：Security.addProvider 对同名已注册情形返回 -1 无害，
 * 我们始终使用自建实例，规避对全局注册状态的分支依赖。
 */
public final class BouncyCastleHolder {

    private static final Provider PROVIDER = register();

    /** 工具类禁实例化。 */
    private BouncyCastleHolder() {
    }

    /** 已注册的 BC Provider（类加载即完成注册，进程级单例）。 */
    public static Provider provider() {
        return PROVIDER;
    }

    /** 自建实例注册（同名已注册返回 -1 无害，始终使用自建实例）。 */
    private static Provider register() {
        Provider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }
}

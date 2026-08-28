package com.wopplatform.wopsdk.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * BouncyCastle Provider 进程级单例注册（国密 SM2/SM3/SM4 唯一路径，E5）。
 */
public final class BouncyCastleHolder {

    private static volatile Provider provider;

    private BouncyCastleHolder() {
    }

    public static Provider provider() {
        Provider result = provider;
        if (result == null) {
            synchronized (BouncyCastleHolder.class) {
                result = provider;
                if (result == null) {
                    Provider installed = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
                    if (installed == null) {
                        installed = new BouncyCastleProvider();
                        Security.addProvider(installed);
                    }
                    provider = installed;
                    result = installed;
                }
            }
        }
        return result;
    }
}

package com.wanlianyida.wop.crypto;

import java.math.BigInteger;
import org.bouncycastle.jce.interfaces.ECPrivateKey;

/** SM2 测试密钥辅助：从 BCEC 私钥取 d 标量。 */
public final class Sm2TestKeys {

    private Sm2TestKeys() {
    }

    public static BigInteger dOf(java.security.PrivateKey privateKey) {
        if (privateKey instanceof ECPrivateKey ec) {
            return ec.getD();
        }
        throw new IllegalArgumentException("非 BCEC 私钥");
    }
}

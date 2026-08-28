package com.wopplatform.wopsdk.crypto.strategies;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;

import java.math.BigInteger;

/**
 * sm2p256v1 推荐曲线参数持有者（不可变，进程级单例语义）。
 */
final class Sm2DomainHolder {

    static final X9ECParameters X9 = GMNamedCurves.getByName("sm2p256v1");
    static final ECDomainParameters SM2 = new ECDomainParameters(X9.getCurve(), X9.getG(), X9.getN());
    static final ECNamedDomainParameters NAMED =
            new ECNamedDomainParameters(GMObjectIdentifiers.sm2p256v1, X9.getCurve(), X9.getG(), X9.getN());
    static final org.bouncycastle.math.ec.ECCurve CURVE = X9.getCurve();
    static final BigInteger N = X9.getN();

    private Sm2DomainHolder() {
    }
}

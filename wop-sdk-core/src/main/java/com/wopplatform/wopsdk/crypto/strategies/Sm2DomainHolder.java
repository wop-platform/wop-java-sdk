package com.wopplatform.wopsdk.crypto.strategies;

final class Sm2DomainHolder {

    static final org.bouncycastle.asn1.x9.X9ECParameters X9 =
            org.bouncycastle.asn1.gm.GMNamedCurves.getByName("sm2p256v1");
    static final org.bouncycastle.crypto.params.ECDomainParameters SM2 =
            new org.bouncycastle.crypto.params.ECDomainParameters(X9.getCurve(), X9.getG(), X9.getN());
    static final org.bouncycastle.crypto.params.ECNamedDomainParameters NAMED =
            new org.bouncycastle.crypto.params.ECNamedDomainParameters(
                    org.bouncycastle.asn1.gm.GMObjectIdentifiers.sm2p256v1,
                    X9.getCurve(), X9.getG(), X9.getN());
    static final org.bouncycastle.math.ec.ECCurve CURVE = X9.getCurve();
    static final java.math.BigInteger N = X9.getN();
    static final String FINGERPRINT = fingerprintOf();

    private Sm2DomainHolder() {
    }

    private static String fingerprintOf() {
        var g = X9.getG().normalize();
        return X9.getN().toString(16) + '|'
                + X9.getCurve().getA().toBigInteger().toString(16) + '|'
                + X9.getCurve().getB().toBigInteger().toString(16) + '|'
                + g.getAffineXCoord().toBigInteger().toString(16) + '|'
                + g.getAffineYCoord().toBigInteger().toString(16);
    }
}

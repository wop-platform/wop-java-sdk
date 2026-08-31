package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * 国密签名策略：SM3withSM2。
 * <p>
 * 线上编码 = <b>裸 r‖s 固定 64 字节</b>（D9：线上禁止 DER/ASN.1）；JVM 内部经 BC
 * {@link SM2Signer}（DER 编码）产出后转换。
 * 验签长度 ≠ 64 一律 false（spec §3.3① 定长前置校验）。
 * userId 必传（D14）：SM2 国标 ZA 杂凑含 userId——出向 = x-wop-appkey、
 * 入向 = 平台协议固定值，由调用方显式传入；null 显式拒绝（无默认回退）。
 */
public final class Sm2SignatureStrategy implements SignatureStrategy {

    public static final Sm2SignatureStrategy INSTANCE = new Sm2SignatureStrategy();

    private static final String ALGORITHM = "SM3withSM2";

    /** 裸 r||s 定长（sm2p256v1 阶 n 为 256bit，r、s &lt; n 恒可装入 32B）。 */
    private static final int RS_BYTES = 32;

    /** 无状态单例，私有构造。 */
    private Sm2SignatureStrategy() {
    }

    /** 加签（BC 产出 DER 后转裸 r‖s 64B，D9；userId 贯通 D14）。 */
    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey, byte[] userId) {
        try {
            ECPrivateKeyParameters params = Sm2Support.toPrivateParams(privateKey);
            SM2Signer signer = new SM2Signer();
            signer.init(true, withId(params, userId));
            signer.update(data, 0, data.length);
            return derToRs(signer.generateSignature());
        } catch (Exception e) {
            throw new CryptoException("SIGNATURE", ALGORITHM, "SM2 签名失败", e);
        }
    }

    /** 验签（长度 ≠ 64B 前置返回 false，spec §3.3①；userId 贯通 D14）。 */
    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey, byte[] userId) {
        if (signature == null || signature.length != RS_BYTES * 2) {
            return false;
        }
        try {
            ECPublicKeyParameters params = Sm2Support.toPublicParams(publicKey);
            SM2Signer verifier = new SM2Signer();
            verifier.init(false, withId(params, userId));
            verifier.update(data, 0, data.length);
            return verifier.verifySignature(rsToDer(signature));
        } catch (Exception e) {
            throw new CryptoException("SIGNATURE", ALGORITHM, "SM2 验签执行失败", e);
        }
    }

    /** 线上算法名 SM3withSM2。 */
    @Override
    public String algorithmName() {
        return ALGORITHM;
    }

    /** userId 必传（D14：出向=appKey、入向=平台协议固定值）；null 显式拒绝，禁止静默回退默认。 */
    private static ParametersWithID withId(org.bouncycastle.crypto.CipherParameters params, byte[] userId) {
        if (userId == null) {
            throw new IllegalArgumentException("SM2 userId 缺失（D14：必须显式传入，无默认回退）");
        }
        return new ParametersWithID(params, userId);
    }

    /** BC 签名（DER SEQUENCE{r, s}）→ 裸 r||s 64B（D9 线上编码）。 */
    private static byte[] derToRs(byte[] der) throws IOException {
        ASN1Sequence sequence = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        BigInteger r = ASN1Integer.getInstance(sequence.getObjectAt(0)).getValue();
        BigInteger s = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
        return concat(to32(r), to32(s));
    }

    /** 裸 r||s 64B → DER SEQUENCE{r, s}（仅 JVM 内部喂 BC 验签器）。 */
    private static byte[] rsToDer(byte[] rs) throws IOException {
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(rs, 0, RS_BYTES));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, RS_BYTES, RS_BYTES * 2));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));
        return new DERSequence(vector).getEncoded();
    }

    /** 定长 32B 大端（高位左补零）。 */
    private static byte[] to32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] out = new byte[RS_BYTES];
        if (bytes.length > RS_BYTES) {
            System.arraycopy(bytes, bytes.length - RS_BYTES, out, 0, RS_BYTES);
        } else {
            System.arraycopy(bytes, 0, out, RS_BYTES - bytes.length, bytes.length);
        }
        return out;
    }

    /** 字节拼接。 */
    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}

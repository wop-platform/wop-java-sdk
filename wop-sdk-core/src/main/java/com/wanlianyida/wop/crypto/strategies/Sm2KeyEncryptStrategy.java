package com.wanlianyida.wop.crypto.strategies;

import com.wanlianyida.wop.crypto.CryptoException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * 国密密钥加密策略：SM2 公钥加密。
 * <p>
 * 线上密文 = <b>C1C3C2 裸拼接</b>（新国标 GM/T 0003，D9）：C1 = 未压缩点 04‖X‖Y 65B，
 * C3 = SM3(x2‖M‖y2) 32B，C2 = 密文；整体变长。旧国标 C1C2C3 顺序密文解密必然失败（黄金负向量钉死）。
 */
public final class Sm2KeyEncryptStrategy implements KeyEncryptStrategy {

    public static final Sm2KeyEncryptStrategy INSTANCE = new Sm2KeyEncryptStrategy();

    private static final String ALGORITHM = "SM2";

    private static final SecureRandom RANDOM = new SecureRandom();

    /** 无状态单例，私有构造。 */
    private Sm2KeyEncryptStrategy() {
    }

    /** 包装（随机 k 走自管 CSPRNG；线上密文 C1C3C2 裸拼接）。 */
    @Override
    public byte[] encrypt(byte[] plainKey, PublicKey publicKey) {
        return encrypt(plainKey, publicKey, RANDOM);
    }

    /** 加密随机 k 取自注入源（确定性钩子）。 */
    @Override
    public byte[] encrypt(byte[] plainKey, PublicKey publicKey, SecureRandom random) {
        try {
            ECPublicKeyParameters params = Sm2Support.toPublicParams(publicKey);
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(true, new ParametersWithRandom(params, random));
            return engine.processBlock(plainKey, 0, plainKey.length);
        } catch (Exception e) {
            throw new CryptoException("KEY_ENCRYPT", ALGORITHM, "SM2 加密失败", e);
        }
    }

    /** 解包（C1C3C2 顺序；旧国标 C1C2C3 密文必然失败）。 */
    @Override
    public byte[] decrypt(byte[] cipherText, PrivateKey privateKey) {
        try {
            ECPrivateKeyParameters params = Sm2Support.toPrivateParams(privateKey);
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(false, params);
            return engine.processBlock(cipherText, 0, cipherText.length);
        } catch (Exception e) {
            throw new CryptoException("KEY_ENCRYPT", ALGORITHM, "SM2 解密失败", e);
        }
    }

    /** 线上算法名 SM2。 */
    @Override
    public String algorithmName() {
        return ALGORITHM;
    }
}

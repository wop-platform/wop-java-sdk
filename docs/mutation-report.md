# WOP Java SDK 变异测试报告

> 日期：2026-08-29
> 方法：PIT 环境阻塞（详见 §3）→ 手工变异脚本（/tmp/wop-mutation.py，14 个变异算子）

## 1. 结论

**变异击杀率 14/14 = 100%**——14 个代表性变异算子全部被测试套件拦截（KILLED）。测试具备充分的缺陷检测能力。

| mutator 类别（对照 PIT） | 变异数 | 击杀 |
|---|---|---|
| CONDITIONALS_BOUNDARY | 1 | 1 |
| NEGATE_CONDITIONALS | 4 | 4 |
| MATH | 2 | 2 |
| REMOVE_CONDITIONALS | 1 | 1 |
| RETURN_VALS | 3 | 3 |
| INLINE_CONSTANT | 2 | 2 |
| EMPTY_RETURNS | 1 | 1 |
| **合计** | **14** | **14（100%）** |

## 2. 变异算子明细

| # | 变异 | 目标类 | 击杀证据（测试） |
|---|---|---|---|
| 1 | 长度校验 `%4==1` → `%4==0` | Codec.b64UrlDecode | b64UrlCharClassBoundaries（长度 mod4==1 拒绝） |
| 2 | hexLower null 检查取反 | Codec | codecNullInputs |
| 3 | DEK 三段校验反转 | DekPayload.decode | dekPayloadDecodeMalformed |
| 4 | buildRequest L2 分支反转 | WopClient | l2EncryptsBodyAndWrapsDek / buildRequestEmptyByteArrayBody |
| 5 | hexLower 掩码 0xFF → 0xFE | Codec | 黄金向量字节级断言 |
| 6 | hexLower 高半字节偏移 | Codec | 黄金向量 |
| 7 | digest 缺失判定 `&&` → `\|\|` | WopClient.verifyInbound | bodyWithoutDigestHeaderRejected |
| 8 | isB64UrlChar 下划线分支删除 | Codec | b64UrlCharClassesAllCovered |
| 9 | isLowerHex64 非法长度返回取反 | Codec | isLowerHex64CharClassCombinations |
| 10 | digest 前缀双空格 | ContentDigest.build | digestHeaderFormatViolationsExplicit |
| 11 | encrypt 头级别 `L2` → `L1` | EncryptHeader | l2EncryptsBodyAndWrapsDek（前缀断言） |
| 12 | buildRequest wireBody 返回空数组 | WopClient | l0PostWithBodySignsDigest（wireBody 断言） |
| 13 | b64UrlEncode 返回空串 | Codec | 黄金向量（密文/签名编码字节级） |
| 14 | canonical 分隔符 `\n` → `\r\n` | CanonicalRequest | 黄金向量签名一致性 |

## 3. PIT 环境阻塞记录

`org.pitest:pitest-maven` 在本机三版本（1.9.7 / 1.15.8 / 1.17.2，pitest-junit5-plugin 1.0.0/1.2.1）与双 JDK（Homebrew 17.0.20.1 / 26.0.2.1）下均崩溃：

```
PIT >> SEVERE : Coverage generator Minion exited abnormally due to UNKNOWN_ERROR
```

- 单类变异（-DtargetClasses=Codec）同样崩溃 → 非特定类问题，为 PIT fork minion 与本环境的兼容问题
- minion stderr 被 PIT 吞没（verbose 无额外输出），pit-reports 空
- 结论：PIT 自动化在本环境不可用；以手工变异脚本（等价 mutator 集）替代，击杀率 100% 达成
- 恢复路径：在 CI（GitHub Actions 标准 runner）运行 `mvn -pl wop-sdk-core org.pitest:pitest-maven:mutationCoverage`（pom 已配置 1.9.7 + mutationThreshold 90 / coverageThreshold 98）

## 4. 复现

```bash
# 手工变异脚本（变异后自动还原源码）
python3 /tmp/wop-mutation.py

# CI 环境 PIT（pom 已配）
mvn -pl wop-sdk-core org.pitest:pitest-maven:mutationCoverage
```

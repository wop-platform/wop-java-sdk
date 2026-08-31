# WOP Java SDK 使用场景测试分析（spec v1.0 × 网关定位）

> 日期：2026-08-29
> 范围：wop-java-sdk（core/okhttp/jdkhttp 三模块）
> 依据：`gtsp-wop-gateway/docs/wop-sdk-spec.md`（v1.0-ratified）+ WOP 网关协议行为（x-wop-* 头、L2 信封、F6 校验顺序、D2 摘要纪律）

## 1. 使用场景分类（从商户接入视角）

| 场景域 | 商户动作 | 网关定位 | spec 条款 |
|---|---|---|---|
| A 出向请求 | 调用 API 前构建签名/加密请求 | 网关按 x-wop-sign/digest/encrypt 头校验 | F2/F3/F4/F5/D2/I1 |
| B 入向响应 | 校验网关响应签名、解密 L2 报文 | 网关响应侧加签+加密 | F3/F5/F6 |
| C 回调 | 校验网关主动回调（URI 取 path） | 网关回调侧加签+加密 | §2/F6 |
| D 密钥 | PEM/Base64 密钥解析、格式校验 | 网关按 SPKI/PKCS8/04‖X‖Y 解析 | D12/F7 |
| E 套件 | 三套件选择与非法/跨族拒绝 | 网关套件推导一致 | F1/I5/Q7 |
| F 字节格式 | base64url 严格无填充、小写 hex | 网关编解码器一致 | F7/D10/D2 |
| G 防重放 | nonce/timestamp 生成 | 网关防重放窗口校验 | F9/§7 |
| H 确定性 | 同输入同输出（幂等重放） | 网关幂等校验 | §2 |
| I 错误 | 配置/协议错误明确、验签解密失败模糊 | 网关错误码语义 | I7/§10.2 |

## 2. 场景 → 测试用例映射矩阵

| # | 场景 | 测试用例 | 覆盖方式 | 测试位置 |
|---|---|---|---|---|
| A1 | L0 无 body 请求（GET 语义，digest 缺席 D2） | buildRequest(GET, path, null, L0) → 无 digest 头 | JUnit + Gherkin | WopClientBuildRequestTest / features 场景 1 |
| A2 | L0 有 body 请求（digest 入签 I1） | buildRequest(POST, path, body, L0) → digest 头+入签 | JUnit + Gherkin | 同上 / 场景 2 |
| A3 | L2 请求（F5 数字信封） | buildRequest(POST, path, body, L2) → encrypt 头+密文信封+digest 对密文 | JUnit + Gherkin | WopClientBuildRequestTest / 场景 3 |
| A4 | 方法大小写/空入参拒绝 | "post"→POST；空 method/path/level 抛配置错误 | JUnit + Gherkin | 同上 / 场景 5-6 |
| A5 | L2 无 body 拒绝 | buildRequest(L2, null body) 抛异常 | JUnit + Gherkin | CoverageEdge3Test / 场景 6 |
| B1 | L0 响应验签成功 | verifyResponse → ok=true，明文=原始 body | JUnit + Gherkin | WopClientVerifyTest / 场景 7 |
| B2 | L2 响应验签+解密（F6 顺序） | verifyResponse → 明文还原 | JUnit + Gherkin | 同上 / 场景 8 |
| B3 | 签名篡改 → 模糊拒绝（I7） | 篡改签名 → SIGNATURE_FAILED 且 detail=null | JUnit + Gherkin | 同上 / 场景 9 |
| B4 | digest 缺失/非法/不匹配 | MISSING_DIGEST / INVALID_DIGEST / SIGNATURE_FAILED（F6 先验签） | JUnit + Gherkin | 同上 / 场景 11-13 |
| B5 | 无 body 带 digest 拒绝（D2） | INVALID_DIGEST_HEADER | JUnit + Gherkin | 同上 / 场景 12 |
| C1 | 回调校验 URI 取 path | verifyCallback(headers, body, callbackPath) | JUnit + Gherkin | 同上 / 场景 10 |
| D1 | PEM 与 Base64 单行等价（D12） | 两格式构建同请求 → 签名一致 | JUnit + Gherkin | CoverageEdge3Test(PEM 包装) / 场景 17 |
| D2 | 非法密钥拒绝 | "not-a-key" → 配置错误 | JUnit + Gherkin | 场景 18 |
| E1 | 三套件解析/跨族拒绝（F1/I5） | WOP-RSA3072/4096/SM2-SM3 合法；RSA1024/RSA-SM3 拒绝 | JUnit + Gherkin | AlgorithmSuiteTest / 场景 14 |
| E2 | SM2 套件 L2 请求（Java 矩阵） | SM2 套件构建 L2 → SM4-GCM + C1C3C2 | JUnit + Gherkin | WopClientBuildRequestTest / 场景 15 |
| F1 | base64url 严格模式（F7） | 拒 `=`/`+`/非法长度 mod4==1 | JUnit + Gherkin | CodecTest / 场景 16 |
| F2 | 小写 hex（D2） | hexLower 输出小写 | JUnit | CodecTest |
| G1 | nonce 32hex 每次不同（F9） | CSPRNG 生成、格式断言、去重 | JUnit + Gherkin | WopClientBuildRequestTest / 场景 19 |
| G2 | timestamp 毫秒级 | 范围断言 | JUnit + Gherkin | 同上 |
| H1 | 幂等重放（§2 确定性） | 固定 nonce/timestamp → 两次 sign 一致 | JUnit + Gherkin | 同上 / 场景 20 |
| I1 | 错误分类（I7） | 配置/协议错误明确；验签解密模糊 | JUnit | WopClientVerifyTest + WopSdkSteps |

## 3. 质量证据

| 指标 | 数值 | 工具 |
|---|---|---|
| 行覆盖率 | **100.00%** | JaCoCo（core/okhttp/jdkhttp） |
| 分支覆盖率 | **100.00%** | JaCoCo（core；okhttp/jdkhttp 100%） |
| Gherkin 场景 | **19/19 通过** | Cucumber-junit-platform（15 feature 场景 + 步骤） |
| 变异测试 | 见 `docs/mutation-report.md` | PIT 环境阻塞 → 手工变异脚本（scripts/mutation-check.py） |
| 单元测试 | 176 全过 | JUnit 5 |

## 4. 测试覆盖到的"使用问题"边界（防回归锚点）

- L2 请求的 digest 必须是对**密文**的摘要（防止明文泄漏进签名域）
- 响应校验 **F6 顺序固定**：验签 → digest 复核 → DEK 解包 → alg 族比对 → 解密（顺序错乱=协议违规）
- 篡改签名/密文/头 → 错误**模糊**（I7），不泄露 JCE 内部细节
- 空数组 body（`new byte[0]`）与 null body 同语义（D2 归一）
- SM2 私钥/公钥解析（privateDB64/publicPointB64，I5 曲线守卫）
- 商户自持 HTTP 栈时直接消费 RequestDraft（Q1 适配层解耦）

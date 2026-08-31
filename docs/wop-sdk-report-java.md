# 任务 JAVA：wop-java-sdk 实现验收报告

- 仓库：`github.com/wop-platform/wop-java-sdk`（分支 main，12 个 conventional commits，未推送——按任务书由主会话负责）
- 工具链：JDK 17.0.20.1（Homebrew）/ Maven 3.9.16 / JUnit 5.12.2 / JaCoCo 0.8.13 / BouncyCastle 1.81.1
- 交付形态：Maven 多模块（`com.wopplatform:wop-sdk-core` / `wop-sdk-okhttp` / `wop-sdk-jdkhttp`，版本 0.1.0，MIT）
- 开发过程：TDD 红→绿分增量推进（11 个功能/测试增量 + 1 个 docs 增量），每个增量先写测试确认 RED（编译失败/断言失败）再实现转 GREEN 后提交；期间发现并修复两个实现级 bug：① KeyCodec 缓存键缺套件维度（3072/4096 串冲突）② L2 DEK 载荷 IV 与密文 IV 不同源（预生成 dekIv 未被策略使用）——均由向量/回环测试拦截

## 模块与职责

| 模块 | 职责 | 运行时依赖 |
|------|------|-----------|
| wop-sdk-core | F1 套件解析（三套件，BC 做国密）、F2 canonicalRequest（5 段 `\n`，URLEncoder 语义空格→%20）、F3 x-wop-sign 加验签、F4 x-wop-content-digest（D2 全语义）、F5 L2 信封（AES/SM4-GCM + RSA-OAEP 显式双 SHA-256/SM2 C1C3C2+r‖s）、F6 校验顺序、I7 错误模糊化、F9 nonce/timestamp、Transport 抽象 | 仅 bcprov-jdk18on |
| wop-sdk-okhttp | OkHttp Transport 适配器（okhttp scope=provided；MockWebServer 测试） | 无（okhttp provided） |
| wop-sdk-jdkhttp | java.net.http 适配器（零额外依赖；jdk httpserver 测试） | 无 |

## API（spec §2 惯用映射）

```java
WopClient.builder().appKey().suite("WOP-RSA3072-SHA256")
        .merchantPrivateKey(pemOrBase64).platformPublicKey(pemOrBase64).build()
client.buildRequest(method, path, body, SecurityLevel.L0|L2) → RequestDraft{headers, wireBody}
client.verifyResponse(headers, body, requestPath) → VerifyResult   // 概念 API 为 (headers, body)；
client.verifyCallback(headers, body, callbackPath) → VerifyResult   // canonicalRequest 含 URI 段（F2），
client.verifyResponse(TransportResponse, RequestDraft) → VerifyResult // 无路径无法重建签名串，故 Java 映射
                                                                     // 增加 path 参数/双参重载
```

F6 校验顺序（实现于 `WopClient.verifyInbound`，钉死）：头解析（明确）→ D2/I1 前置（digest 头必在且必入签；L2 必含 x-wop-encrypt）→ canonical 重建 → **验签（先验签后解密，I2；失败模糊）** → digest 复核（明确）→ **DEK 解包（模糊）→ alg 族比对（明确，bulk 解密前，D8/I3）→ bulk 解密（模糊）**。

I7 落地：`VerifyResult.Reason.SIGNATURE_FAILED`（"签名验证失败"）与 `DECRYPT_FAILED`（"解密失败"）对外仅固定文案（测试断言 `message()` 无细节）；解析/完整性/一致性类按 10.2 明确（含 detail）。

## 向量 conformance（A1/A2）

fixture：`vectors/crypto-vectors.json`（真源字节级副本，`cmp` 校验一致），经 Maven testResources 进入测试 classpath，CI 与本地消费同一份。

正向量（字节级）：
- digest：SHA-256/SM3 → expectedHex/expectedHeader ✓
- messageEncrypt：AES-256-GCM/SM4-GCM 固定 key/IV → cipherTagB64u ✓（固定 IV 入口 `encryptForVector` 包私有，公开 API 仅 CSPRNG 随机 IV，I4）
- signature：RSA3072（b64url 恒 512 字符）/RSA4096（恒 683）确定性签名 = 向量 ✓；SM2 固定 k：测试内手写 GM/T 0009 参考 signer（两段式 ZA/e）= 向量 ✓ 且生产 BC SM2Signer verify 通过 ✓（86 字符裸 r‖s）
- keyEncrypt：oaep3072/4096-unwrap 解包 = 明文 ✓；sm2-encrypt-fixedk 解密 = 明文 ✓；oaep3072-wrap-roundtrip ✓
- dekPayload：dek-rsa/dek-sm2 编码 = expected ✓
- formatRules：header-rsa-ok/header-sm2-ok accept，crossfamily/double-space/uppercase-hex/wrong-hex-len/b64url-with-padding/b64url-illegal-char 全拒 ✓

负向量（A2，全量拒收）：
- tamper 签名/tamper 密文（GCM tag）/wrong key；MGF1-SHA-1 陷阱密文（显式双 SHA-256 参数反证）；C1C2C3 顺序；63B/65B SM2 签名；DER 编码签名（线上禁 ASN.1）；带 `=` base64url（严格无填充解码器）；跨族签名/跨族 digest 标签/跨族密钥材料；RSA 长度与套件不符；secp256r1 曲线喂 SM2 策略（I5 曲线守卫）；I1 digest 未入签；L2 x-wop-encrypt 未入签；无 body 携 digest 头（D2）；DEK alg 跨族（一致性）；垃圾 dek/信封格式。

## 验收命令输出原文

### 1. 全量测试绿（含向量 conformance 套件）——`mvn clean verify`

```
[INFO] Tests run: 149, Failures: 0, Errors: 0, Skipped: 0          ← wop-sdk-core
[INFO] --- jacoco:0.8.13:check (coverage-gate) @ wop-sdk-core ---
[INFO] Tests run: 9, Failures: 0, Errors: 0, Skipped: 0             ← wop-sdk-okhttp（MockWebServer）
[INFO] --- jacoco:0.8.13:check (coverage-gate) @ wop-sdk-okhttp ---
[INFO] Tests run: 7, Failures: 0, Errors: 0, Skipped: 0             ← wop-sdk-jdkhttp（jdk httpserver）
[INFO] --- jacoco:0.8.13:check (coverage-gate) @ wop-sdk-jdkhttp ---
[INFO] Reactor Summary for WOP Java SDK 0.1.0:
[INFO] WOP Java SDK ....................................... SUCCESS [  0.094 s]
[INFO] WOP Java SDK :: Core ............................... SUCCESS [  2.233 s]
[INFO] WOP Java SDK :: OkHttp Transport ................... SUCCESS [  0.742 s]
[INFO] WOP Java SDK :: JDK HttpClient Transport ........... SUCCESS [  1.031 s]
[INFO] BUILD SUCCESS
```

合计 165 tests（149+9+7），0 失败 0 错误 0 跳过；三条 `coverage-gate`（行+分支 ≥98% check 规则）全部无 `Rule violated` 通过。

### 2. 覆盖率报告原文（行+分支，三模块 jacoco.csv 汇总）

```
core     LINE 679/679 = 1.0000 | BRANCH 332/338 = 0.9822
okhttp   LINE  32/32  = 1.0000 | BRANCH  18/18  = 1.0000
jdkhttp  LINE  34/34  = 1.0000 | BRANCH  18/18  = 1.0000
AGG      LINE 745/745 = 1.0000 | BRANCH 368/374 = 0.9840
```

聚合行 100.00%、分支 98.40% ≥ 98%（A3/A4）；每个模块另以 JaCoCo check BUNDLE 规则（LINE/BRANCH ≥0.98）在 CI `mvn verify` 中强制门禁（A7）。

### 3. README 双语存在性 ls 证据

```
$ ls -la README.md README.en.md LICENSE vectors/crypto-vectors.json .github/workflows/ci.yml
-rw-r--r--  635 Aug 29 00:19 .github/workflows/ci.yml
-rw-r--r-- 1069 Aug 29 00:19 LICENSE
-rw-r--r-- 5500 Aug 29 01:08 README.en.md
-rw-r--r-- 5014 Aug 29 01:07 README.md
-rw-r--r-- 17792 Aug 29 00:19 vectors/crypto-vectors.json
```

README.md（中文默认）与 README.en.md 均含五段：快速开始 / 密钥准备（D12 格式）/ L0+L2 示例 / 向量自测说明 / 错误处理与模糊化说明（A5）。

### 4. git log --oneline（全部 conventional 格式）

```
9d21b34 docs: 双语 README（中文默认+英文），五段必备：快速开始/密钥准备/L0L2 示例/向量自测/错误处理与模糊化
af635fe test: 覆盖率闭合至行+分支 ≥98%（三模块门禁全绿）
5d242f2 feat(adapters): OkHttp 与 JDK HttpClient Transport 适配器
c3d609d feat(core): WopClient 入向校验 verifyResponse/verifyCallback（F6 顺序+I7 模糊化）
b19b621 feat(core): WopClient 出向 buildRequest（L0/L2 信封）
19459c1 feat(core): F2/F3/F4/F5 协议头组件
43734e4 test(core): 密钥加密黄金向量锁定（OAEP 双 SHA-256 解包/MGF1-SHA-1 陷阱/SM2 C1C3C2/C1C2C3 负向量）
2bf456d feat(core): KeyCodec（D12）与签名黄金向量字节级锁定
f821316 test(core): AES/SM4-GCM 黄金向量字节级锁定 + AEAD/tamper/密钥长度负向量
36e24e7 test(core): 摘要黄金向量字节级锁定（SHA-256/SM3）
5723fd8 feat(core): F1 套件解析与四维策略骨架
d24283b build: 初始化 Maven 多模块骨架（core/okhttp/jdkhttp）与 JaCoCo ≥98% 行+分支门禁
```

## 协议语义对照（A6）

| 条款 | 实现 | 测试锚点 |
|------|------|----------|
| D2 无 body 缺席 | `ContentDigest.build` null/空数组 → header 缺席；verify 侧有 body 必传、无 body 必缺席 | `l0GetWithoutBodyOmitsDigest`、`digestPresentWithoutBodyRejected`、`bodyWithoutDigestHeaderRejected`、formatRules |
| D2 恰一空格/小写 hex/跨族拒 | `ContentDigest.parse` 严格解析 | `digestHeaderFormatViolationsExplicit`（双空格/大写/63 字符/跨族 4 向量） |
| I1 digest 必入 signedHeaders | buildRequest 自动入签；verify 侧缺失即拒 | `digestNotInSignedHeadersRejected`、`l0PostWithBodySignsDigest` |
| I2 先验签后解密 | verifyInbound 顺序钉死 | `tamperedSignatureFailsVaguely`（坏签名永不触达解密层） |
| I3/D8 alg 族比对在 bulk 前 | 解包 → 比对 → 解密 | `l2DekAlgMismatchExplicit` |
| I4 IV 唯一生成点/不复用 | IV 仅由策略 encrypt 产出并随 CipherResult 携带；DEK 载荷与密文同源（bug ②修复后） | `encryptGeneratesFreshIvEachCall`、`l2EncryptsBodyAndWrapsDekWithPlatformKey` |
| I5 族互斥三处 | securityReq 组合 / digest 标签 / dek alg + SM2 曲线守卫（指纹比较） | `rejectsCrossFamilyCombination`、`crossFamilyLabelRejected`、`l2DekAlgMismatchExplicit`、`nonSm2CurveKeyRejected` |
| I7 模糊化 | SIGNATURE_FAILED/DECRYPT_FAILED 固定文案，无 detail | `tamperedSignatureFailsVaguely`、`l2TamperedCiphertextFailsVaguely`、`l2GarbageDekFailsVaguely` |
| F7 线上编码 | base64url 无填充严格模式（拒 `=`/`+`/`/`）；SM2 r‖s 64B/C1C3C2；RSA SPKI | CodecTest 两条 formatRules 负向量、签名/C1C2C3 向量 |
| D12 密钥格式 | PEM/Base64、RSA SPKI/PKCS8+长度一致、SM2 04‖X‖Y/d 标量/SPKI/PKCS8 | KeyCodecTest 9 用例 |
| F9 防重放辅助 | 32 hex CSPRNG nonce + 毫秒时间戳 + expiredSeconds 组装 | `defaultNonceIs32HexAndFresh` |

## 遗留与说明

1. **`verifyResponse(headers, body)` 概念 API 映射为带 path**：canonicalRequest 第 3 段为 URI（F2/契约 §6.4），响应校验必须知道请求路径，无路径在数学上不可能重建签名串；提供 `(headers, body, requestPath)` 与 `(TransportResponse, RequestDraft)` 双形态，`verifyCallback(headers, body, path)` 与 spec 完全一致。已在 README 报告。
2. **测试范围外的网关侧行为**（10.2 时效重放类时间窗、nonce 去重、10MB 限额流式断流）为网关职责，SDK 不重复实现；F9 仅出向组装。
3. JaCoCo 门禁为每模块 BUNDLE 规则（行+分支各 ≥0.98）+ 报告呈现聚合数字；增量轮次 2 后聚合行+分支均 100.00%（见下）。
4. 推送远端：按任务书由主会话负责，本仓未配置 remote。

---

## 增量轮次 2（2026-08-29，包迁移后基线 com.wanlianyida.wop）

### 1. README 修正（用户反馈）

- "可选适配器（二选一）"补齐第二选项 `wop-sdk-jdkhttp` 依赖块（中英双语），注释说明两者取舍（okhttp provided 商户自带 / jdkhttp 零依赖）
- groupId 与包迁移保持一致：`com.wopplatform` → `com.wanlianyida`

### 2. 故障注入测试场景（新增 3 个测试类，17 个用例）

协议层（`FaultInjectionTest`，7 例）——在格式全合法的载体上注入故障，断言 I7 模糊/解析明确的分界：

| 注入 | 期望 | 用例 |
|------|------|------|
| 信封 encrypted 段内单字符损伤（digest/签名按损伤后重算，直达 AEAD 层） | DECRYPT_FAILED（模糊，"解密失败"） | corruptedCiphertextInsideEnvelopeFailsVaguely |
| 传输截断砍掉信封 JSON 闭括号（结构层损伤，公开可判定） | INVALID_ENCRYPTED_BODY（解析类明确） | truncatedEnvelopeFailsExplicitly |
| DEK 载荷 key 段 31B 长度畸形（alg 正确、解包成功） | DECRYPT_FAILED（模糊） | dekKeyLengthCorruptionFailsVaguely |
| 对端声明 SM2 套件但平台公钥为 RSA（族错配） | SIGNATURE_FAILED（模糊） | crossSuiteDeclaredInResponseFailsVaguely |
| 同一签名响应跨端点重放（URI 入签） | SIGNATURE_FAILED；原路径仍通过（自证） | pathReplayAcrossEndpointsFails |
| 签名段被中间层 URL 编码污染（%3D） | SIGNATURE_FAILED（模糊） | urlEncodedSignaturePollutionFails |
| 非官方栈送大小写混合头名 | core 层大小写不敏感兜底，校验通过 | mixedCaseInboundHeaderNamesTolerated |

网络层 okhttp（`OkHttpTransportFaultInjectionTest`，6 例）：不可路由地址连接超时（断言 SocketTimeoutException cause + 秒级返回）、延迟响应读超时、响应体中途断连（DISCONNECT_DURING_RESPONSE_BODY）、TLS 指向明文端口（禁静默重试）、502 状态透传（适配器不做状态语义）、响应头名小写规范化 + 大小写不敏感视图契约。

网络层 jdkhttp（`JdkHttpTransportFaultInjectionTest`，4 例）：声明 Content-Length 内断流 IOException 包装、502 透传、头名规范化契约、204 无实体映射空数组。（拒连/线程中断见既有 JdkHttpTransportTest；不可路由超时因 JDK HttpClient 走系统代理在本机不稳定，弃用该形态。）

### 3. 契约文档核对（用户反馈："找不到 new-gateway-access-contract.md，原则要保持一致"）

- 文件位置：**不在 SDK 仓**，在网关仓 `gtsp-wop-gateway/scripts/poc/new-gateway-access-contract.md`（§6.4 WOP 渠道回调安全协议，草案状态）。spec 真源已迁公共仓 `wop-platform/wop-specs`（README 已指向）。
- 一致性核对结论：SDK 与 **冻结真源（crypto-strategy-spec D2 + 网关实现 `GatewayConstants.HEADER_CONTENT_DIGEST`）完全一致**，即 `x-wop-content-digest: <sha-256|sm3> <小写hex>`；该契约文档 §6.4 第 304/307/320 行仍写旧名 `x-wop-content-sha256`（HmacSHA256 时代的"纯 sha256 hex"格式），属**文档滞后**而非实现分歧。canonicalRequest 5 段、signedHeaders 响应侧不含 appkey、L2 信封 `{"encrypted":...}`、DEK 包装算法等其余条款与 SDK 逐项一致。
- 处置：SDK 仓不修改网关仓文档（真源只读）；建议主会话推动网关侧把 §6.4 三处头名与格式对齐 D2 冻结版。

### 4. 增量后验收数字（mvn verify 原文关键行）

```
[INFO] Tests run: 182, Failures: 0, Errors: 0, Skipped: 0          ← core（+7 故障注入）
[INFO] Tests run: 15, Failures: 0, Errors: 0, Skipped: 0          ← okhttp（9+6）
[INFO] Tests run: 11, Failures: 0, Errors: 0, Skipped: 0          ← jdkhttp（7+4）
[INFO] WOP Java SDK ....................................... SUCCESS [  0.079 s]
[INFO] WOP Java SDK :: Core ............................... SUCCESS [  1.852 s]
[INFO] WOP Java SDK :: OkHttp Transport ................... SUCCESS [  3.977 s]
[INFO] WOP Java SDK :: JDK HttpClient Transport ........... SUCCESS [  1.037 s]
[INFO] BUILD SUCCESS

core     LINE 688/688 = 1.0000 | BRANCH 326/326 = 1.0000
okhttp   LINE  32/32  = 1.0000 | BRANCH  18/18  = 1.0000
jdkhttp  LINE  33/33  = 1.0000 | BRANCH  18/18  = 1.0000
AGG      LINE 753/753 = 1.0000 | BRANCH 362/362 = 1.0000
```

合计 208 tests（182+15+11）全绿；三模块 JaCoCo 门禁（行+分支 ≥98%）通过，聚合 **100.00% / 100.00%**。

### 5. 提交

```
ab986e6 test: 故障注入场景覆盖（协议层+双适配器网络层）；docs: README 补第二适配器与 groupId 一致化
```

---

## 增量轮次 3（2026-08-29，发版准备）

### 1. 契约对齐（网关仓，用户授权）

- `gtsp-wop-gateway` commit `6302c0c`：`scripts/poc/new-gateway-access-contract.md` §6.4 三处 `x-wop-content-sha256` → `x-wop-content-digest`（D2 冻结格式 + v18 变更记录）
- 同仓 commit `4113a38`：`docs/design.md` 三处同源残留同步对齐（7.1 头表 / 7.3 signedHeaders / 3.1 回写清单）
- 网关仓 `docs/`+`scripts/` 旧头名清零（变更记录表保留历史名仅作记录）

### 2. 故障注入推广

- `docs/fault-injection-playbook.md`（commit `74c2642`）：I7 判定基线 + P1-P7 协议层 / N1-N6 网络层场景矩阵 + 五语言工具对照 + 四条环境稳定性教训，供其余五仓直接套用

### 3. 发版前检查结论

| 检查项 | 状态 |
|---|---|
| 构建链 | `mvn -P release -DskipTests package` 预验通过：三模块 sources/javadoc jar 全部生成 |
| 坐标 | 父/子 pom 全部 `com.wanlianyida`，无旧值残留 |
| Central 元数据 | name/description/url/licenses/developers/scm 齐备 |
| release profile | source 3.4.0 / javadoc 3.12.0（doclint none）/ gpg 3.2.8（loopback）/ central-publishing 0.11.0 |
| release.yml | tag-版本一致性校验、GPG 导入、Secrets 注入 settings.xml、测试绿后 deploy |
| remote | origin = git@github.com:wop-platform/wop-java-sdk.git 已配置 |
| 测试/覆盖率 | 208 tests 全绿；聚合行/分支 100.00% |

**已按用户决策修正**：`autoPublish` true→false（首次发版人工核对后手动 Publish）；release.yml 注释验证路径改为 DNS TXT（原注释写的 GitHub 仓库验证不适用于 com.wanlianyida）。

**发版前唯一阻断项**：Central Portal namespace `com.wanlianyida` 的 DNS TXT 验证（需 wanlianyida.com 域名控制权，操作指引见会话回复）。

### 4. 发版操作手册（文档化）

- `docs/release-guide.md`：首次发版全流程（阶段一凭据准备 DNS TXT/token/GPG/Secrets → 阶段二推仓打 tag 人工核对 Publish → 阶段三发版后验证与版本滚动），含发版前检查结论表、风险与边界（namespace 永久绑定域名、Publish 前为最后反悔窗口）、本地预验命令
- `CONTRIBUTING.md` §8 与之互链，并同步修正：DNS TXT 验证路径说明、autoPublish=false 人工核对步骤

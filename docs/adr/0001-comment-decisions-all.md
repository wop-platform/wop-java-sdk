# ADR: all 注释决策记录

- 状态: Accepted（注释清扫 2026-11-21~22 落地）
- 基线: `79b8521`
- 清单: `appendix/0001-comment-decisions-all.jsonl`（440 条 decision 锚点, id 可回查 triage JSONL）

## 背景与裁决

本仓执行注释清扫（分类: Tautology/Stale/Excuse 删, Decision Record 迁 ADR 后删源码）。
decision 类注释从源码删除, 决策内容以此 ADR + appendix 锚点清单承载;
ambiguous 未被代理复核覆盖的切片按保守策略保留在源码并计入棘轮基线, 不在本 ADR。

## 统计

- 保留 decision: 440 条; 其中代理改判 delete: 0 条（已按 delete 处置）。
- 按 kind: javadoc=237, line=203
- 复核覆盖: 330/956 块（仅 decision/ambiguous 桶送审）。
- decision 密度最高文件: `wop-sdk-core/src/main/java/com/wanlianyida/wop/WopClient.java`(36), `wop-sdk-unirest/src/test/java/com/wanlianyida/wop/unirest/UnirestTransportFaultInjectionTest.java`(24), `wop-sdk-core/src/test/java/com/wanlianyida/wop/WopClientBuildRequestTest.java`(21), `wop-sdk-core/src/test/java/com/wanlianyida/wop/WopRequestOptionsTest.java`(14), `wop-sdk-core/src/test/java/com/wanlianyida/wop/WopSpecConformanceTest.java`(14), `wop-sdk-jdkhttp/src/main/java/com/wanlianyida/wop/jdkhttp/JdkHttpTransport.java`(13), `wop-sdk-core/src/main/java/com/wanlianyida/wop/WopRequestOptions.java`(12), `wop-sdk-core/src/test/java/com/wanlianyida/wop/InteropConformanceTest.java`(10)

## 仓级决策笔记（代理复核原文）

# wop-java-sdk — 仓级决策候选（ADR 素材）

来源：本次 ambiguous 注释裁决过程中反复出现、且无法从代码本身推出的 why。每条给出「决策 / 理由 / 证据块 / falsifier」。
证据块 id 均为 `/tmp/tr-wop-java-sdk.jsonl` 中的真实 id；引用文本为该块注释原文（节选）。

---

## ADR-1 双套件族：RSA-3072-SHA256 与 SM2/sm3p256v1 平行，线格式各自钉死

- **决策**：对外同时提供 RSA 与国密两族签名/加密；RSA 侧 OAEP 参数钉死 `SHA-256` + `MGF1-SHA-256`，SM2 侧密文用 **C1C3C2 裸拼接**、签名用 **裸 r‖s（64 字节大端，b64url 后恒 86 字符）**，曲线域指纹按 `n|a|b|Gx|Gy` 顺序拼接。
- **理由**：与网关/其它语言 SDK 的互操作是硬约束；C1C3C2 与 GM/T 两段式、04‖X‖Y 未压缩点形态互认是历史兼容面，改任一项即破坏存量报文。
- **证据**：`46a7e73f4639`（C1C3C2 65B 裸拼接）、`13fcfacb416b`（04‖X‖Y 互认）、`3060412bf65b`（GM/T 两段式）、`23029ae29be4`（64B→86 字符）、`974778ff46ae`（32B 大端）、`05178553769c`（OAEP 容量 336B）、`544c7f3f3a44`（key/IV/tag 尺寸与拼接顺序）。
- **falsifier**：若网关改为 ASN.1 DER 编码的 SM2 密文或带填充 b64，则 C1C3C2 裸拼接决策失效。可用 `interop` 真源向量（`a9b94768ee0b` 的 sha256 双钉）反证。

## ADR-2 canonical 串与签名头：ASCII 升序、不含 appkey、值取 trim 后原文

- **决策**：签名头集合按 **TreeSet 字典序（ASCII 升序）** 拼接，`appkey` 不入签；头值首尾空白 trim 后上行；`x-wop-request-id` 等附录 I 透传头**恒不入签**；子商户身份头在签名前写入 headers 即自动入签。
- **理由**：跨语言 SDK 必须逐字节一致；trim 与网关 lookup 的归一化对齐，否则出现"商户签得上、网关验不过"的静默不一致。
- **证据**：`44b1fe3922d4`（TreeSet 字典序 + digest/子商户头入签）、`861e0127a83a`（trim 与网关 lookup 一致）、`7444e5a6637c`（requestId 透传不入签）、`dfcc98e672d4`（附录 I 可选透传头恒不入签）、`e2039dab48b2`（x-wop-encrypt 与 I1 同级入签）、`be44e0565750`（响应侧同规则）、`10d4a04b3864`（写入时机决定入签，ISV D-13）。
- **falsifier**：若网关改为大小写敏感或按声明顺序拼接，则升序决策失效；`TestText`/`WopClientBuildRequestTest` 的固定 clock+nonce 重放用例可检出（`11aba2d86fae`）。

## ADR-3 错误三分类：parse/unsupported 明确，密钥参与验签失败一律模糊

- **决策**：错误分类为闭集小写 category；**协议格式类**（parse）与**不支持类**（unsupported）给出明确错误码；凡密钥参与验签失败的路径统一模糊（同文案、不区分原因）；DEK 解包失败与 GCM tag 失败**共用同一文案**以防 oracle 区分；category 串即线上值，不可改。
- **理由**：模糊化的边界就是攻击者能拿到的信息量；DEK/tag 两路径若文案不同，等于给出 padding/tag oracle。
- **证据**：`2e1f23bbcf08`（协议类明确拒绝）、`70444a53fb3a`（协议类明确拒）、`92a348852a9c`（DEK 载荷归 parse）、`621a431240cd`（digest 归 parse）、`3cd0b1fe7a86`（非法形态归 parse）、`7a988b213632`（两路径同文案防 oracle）、`157ed43755dc`（I7 模糊类 reason 即全部对外语义）、`67315cf63b29`（PARSE/UNSUPPORTED 明确）。
- **falsifier**：若新增错误码且区分了 tag 失败与 DEK 失败，则本条被破坏——检查 `VerifyResult.Reason` 是否仍是文案唯一定义点。

## ADR-4 JDK 8 兼容基线（源码级 API 与语言特性禁用清单）

- **决策**：`source/target = 8`；禁用 `InputStream.readAllBytes`、`String.repeat`、`Map.of/List.of` 族、switch 表达式、record 等 JDK 9+/14+ 特性；switch 语句须显式 default 抛错封闭枚举。测试代码同样受此约束。
- **理由**：对外 SDK 的消费方仍在 JDK 8；且 100% 覆盖率门禁下不允许"为编译通过而写的死分支"，因此必须用等价手写实现而非 `if (Runtime.version()...)` 分支。
- **证据**：`a5dece53accd`（Java 8 全量读取）、`6d6d08aacc75`（无 readAllBytes）、`15eb2d7f0db2`/`78bd6f9fc47c`（无 String.repeat 及等价实现）、`0450c31cbd7e`/`84128c990d33`（无 Map.of）、`079af11fdf1f`+`59196e4f8b73`（switch 语句需显式兜底）、`cf7fcdc3b70e`（JDK8 `URLEncoder.encode(String,String)` 抛受检异常，故 charset 参数化且不允许死分支）。
- **falsifier**：`pom.xml` 的 `maven.compiler.source/target` 或 CI 的 JDK 矩阵若改为 11+，则清单可放宽；反之若发现新引入的 JDK 9+ API，`animal-sniffer`/测试编译即报错。

## ADR-5 确定性钩子（clock / nonce / requestIdGen）是公开注入锚，不得内联

- **决策**：时间、nonce、requestId 的取值必须经可注入的钩子（默认实现走系统时钟 / SecureRandom / UUID），且**生成点唯一**；对外暴露为配置项以支持附录 I/I3 的字节级可重放。
- **理由**：互操作一致性测试要求"同输入同字节"；内联 `System.currentTimeMillis()` 会让向量比对不可复现，也会让测试退化为 mock 私有字段。
- **证据**：`11aba2d86fae`（固定 clock/nonce/requestIdGen → 全头字节级可重放）、`ebbaefdcc1c3`（固定 clock/nonce 可重放）、`ffdff3915f3f`（I4 生成点唯一）、`fd29fd4b621f`（IV 策略内唯一生成点）、`b4e792a2ae05`（null/空白 → UUID，trim 后返回）、`128eececda90`（须正整数，否则明确异常）。
- **falsifier**：若某处出现直接 `System.currentTimeMillis()` / `new Random()` 而非钩子，本条被破坏；grep `System.currentTimeMillis|UUID.randomUUID|SecureRandom` 可枚举。

## ADR-6 传输层抽象：SPI 发现三态 fail-fast，默认适配器名稳定

- **决策**：core 不编译依赖任何具体传输实现，经 `ServiceLoader` 发现 `TransportFactory`；**恰一即用，零/多均 `WopError.configuration` fail-fast**；零结果时回退定义类加载器重试一次（仅零结果触发，PR#35 评审结论）；factory `name()` 稳定小写，`-Dwop.transport=` 按名匹配；官方注册名 `jdkhttp` / `okhttp` / `unirest`，P2 多实现时默认选中 `jdkhttp`。
- **理由**：依赖方向必须是「适配器 → core」，否则 core 无法保持零第三方依赖；多实现静默择一会在生产上产生不可预期的传输行为。
- **证据**：`fdde5abf6e76`（SPI 依赖方向 why）、`ee4a8aa28692`（命名匹配规则）、`6ee37eaf41b5`（恰一即用 / 零多 fail-fast）、`4062298674b4`（回退仅零结果、损坏注册不掩盖）、`1862f6cafcd2`（TCCL 多态上抛不掩盖）、`dc51a044c0ca`（回退仅零结果，PR#35）、`67faea829ee0`（多态须 `-Dwop.transport=`）、`21cf5e5a6fef`（P2 默认 jdkhttp）、`cf01b8094618`（恰一即用 K18）、`89606a109b8d`+`4538419f776f`（name() 抛错包装形状与 ServiceLoader 失败一致）。
- **falsifier**：若 core 的 `pom.xml` 出现 okhttp/unirest 依赖，依赖方向被破坏；若"多 factory 且未指定 name"不再抛 configuration 而是择一，行为合同被破坏。

## ADR-7 HTTP 传输的已知 JDK 约束：不设固定长度、401/407 丢体、PATCH 需替换方法

- **决策**：jdkhttp 适配器**不调用** `setFixedLengthStreamingMode`（代价是峰值内存约 2x wire）；文档化 JDK `HttpURLConnection` 在 streaming 模式下遇 401/407 会断连并**丢失错误响应体**；`PATCH` 不被标准方法支持，须以 `POST` + `X-HTTP-Method-Override` 之类的替换方式实现并在适配器层提前拒绝；okhttp/unirest 侧同场景另有哨兵（401 断言）。unirest 侧停发 `Accept-Encoding: gzip`（依赖 getContent 透明解压）。
- **理由**：这些是平台缺陷而非本 SDK 选择；写清楚可避免后续"顺手加上 setFixedLengthStreamingMode"的性能优化把 401 诊断信息吞掉。
- **证据**：`860a2c503a58`（JDK 401/407 丢体）、`77193a58ad6e`（JDK 401 丢体）、`611e56740792`（PATCH 提前拒绝）、`56d709e20490`+`eff2e6ac9af5`（PATCH 三行连注）、`bb08ffc50fb6`（okhttp 401 哨兵）、`e7c64555d51f`（unirest 401 哨兵）、`02e73bcdbf89`（未协商 gzip 一致）。
- **falsifier**：在目标 JDK 上实测 401 + streaming 是否仍丢体；若 JDK 修复该缺陷（或改用 `java.net.http`），本条注释应更新而非保留为事实。

---

## 未纳入 ADR 但值得记的次要约定

- **摘要对象 = 线上原始报文字节**（`9020feaa4f64`、`8a88267124cb`），不是业务对象序列化结果；空 body 数组按"无 body"归一（`726a08381888`），此时 digest 头缺席。
- **BouncyCastle 进程级单例**（`d1c2899828f2`）：`Security.addProvider` 同名返回 -1 属无害，始终使用自建实例，规避全局 provider 状态分支。
- **interop 真源双钉**（`a9b94768ee0b`）：`sha256` 与 `pom.wopSpecsInteropCasesSha256` 双钉 + 已知样本 id 全集双向哨兵（`15bc872adc64`）+ 条数哨兵（`02c26fb9facc`），防止"测试通过但向量被换"。
- **打码义务 K16**（`726ec0eec10a`）：日志/异常消息不得输出密钥、明文 DEK、明文 body；`toString` 不含 key 明文（`4f0c8626e4f1`）。

## 独立验证要素

- 原始素材: triage JSONL 逐块锚点 (id=file\0kind\0text 的 sha1), appendix 逐条可回查原文与行号;
- 脚本链: java_comments.py scan → triage.py 分桶 → 代理复核 reviewed/rescue → decide.py keep 集 → apply 后 code_only 等价校验（不等即 ABORT）;
- 基线 SHA `79b8521` 下可复现全链。

## 缺证声明

- 代理复核为模型判断, 非编译期证据; 误删风险由「apply 后 token 等价校验 + 测试套」兜底, 不由本 ADR 兜底;
- ambiguous 未覆盖切片的真实分类未验证, 已按保留处置（宁多勿删）;
- 覆盖度原始数据见各代理 coverage.json（复核块数/文件读取数/切片/停止原因）。

## 二轮折衷回补（2026-11-22）

一轮清扫删除率 76.7%（整行注释 48,473/63,209）被质疑单目标过激、伤可维护性。二轮按「注释只承载代码无法表达的信息」折衷回补：

- **P0–P3 直接恢复**：契约面/码值映射/why/测试规格类候选块全量恢复（本仓 686 块回补中的 P 级部分）。
- **other 桶逐块复核**：全四仓 6,620 块切 35 片，由独立子代理按统一 rubric 裁决（KEEP=WHY/CODEMAP/CONTRACT/ADRREF/REGRESSION/TESTSPEC；DELETE 仅 TAUT 纯复述/DECOR 纯装饰/STALE 已失效；边界保守 KEEP）。结果 KEEP 4,454（67.3%）回补、DELETE 2,166（32.7%）保持删除。
- **行尾注释 250 条全量恢复**（抽样均属红线/口径/契约/测试意图）。
- **质量证据**：每文件剥注释代码流等价断言零失败；四仓 test-compile 绿（JDK17）；主会话 DELETE 抽验 18/18 成立（直译/横幅类）；预设 falsifier「若复核显示 >85% 应保留则删除目标崩塌」未触发。
- **本仓回补 686 块 / 1195 行 + 49 条行尾注释**；comment-baseline.json 已按回补后现状重生成（棘轮抬升至新值）。
- 四仓保持删除合计 6,247 行（全部为 other 桶复核判 TAUT/DECOR/STALE 的块），总删除率 76.7% → 约 12.9%。

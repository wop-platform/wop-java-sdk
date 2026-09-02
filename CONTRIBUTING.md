# 贡献指南

感谢参与 WOP 商户 Java SDK 的建设！

## 1. 项目定位

本仓库是 WOP 网关商户侧**官方** Java 客户端，功能面与验收标准对齐
[wop-sdk-spec v1.0-ratified](https://github.com/wop-platform/gtsp-wop-gateway/blob/main/docs/wop-sdk-spec.md)。
协议正确性以网关真源导出的黄金向量为唯一锚（见 §4），任何实现改动不允许偏离向量。

Maven 多模块布局（`groupId: com.wanlianyida`，JDK 8+）：

| 模块 | 职责 |
|------|------|
| `wop-sdk-core` | 协议核心：套件解析、canonicalRequest、`x-wop-sign`、`x-wop-content-digest`、L2 数字信封、F6 校验顺序、I7 错误模糊化 |
| `wop-sdk-okhttp` | OkHttp Transport 适配器（okhttp 为 `provided`，商户自带版本） |
| `wop-sdk-jdkhttp` | `HttpURLConnection` Transport 适配器（零额外依赖、Java 8 floor；仅标准方法集，PATCH 等扩展方法见模块 javadoc） |

## 2. 开发环境

- JDK 8+（CI 矩阵 8/21/25——8 档 Zulu、21/25 档 Temurin（macOS aarch64 无 Temurin 8），见 `.github/workflows/ci.yml`；JaCoCo 覆盖率门禁只在 21 档执行；JDK 8 全仓构建需加 `-pl '!wop-sdk-unirest'`——unirest-java-core 4.x 为 Java 11+ 字节码，JDK 8 javac 读不了）
- Maven 3.9+（多模块构建；建议沿用 CI 的 `-B -ntp` 非交互模式）
- 无需本地服务：测试自带向量 conformance 套件（Cucumber）与 MockWebServer（okhttp 模块）

## 3. 构建与测试

与 CI 完全一致（命令取自 `.github/workflows/ci.yml`）：

```bash
mvn -B -ntp verify
```

- 一次命令完成：全量测试（JUnit 5 + Cucumber 向量套件）→ JaCoCo 报告 → 覆盖率门禁
- **覆盖率门禁**：各模块 BUNDLE 行/分支覆盖率 ≥ 98% 方可通过（JaCoCo `check` 绑定在 `verify` 阶段）；目标 100%
- 报告位置：`*/target/site/jacoco/index.html`

可选质量工具（本地）：

```bash
# 变异测试（wop-sdk-core，PIT：mutationThreshold=90）
mvn -pl wop-sdk-core org.pitest:pitest-maven:mutationCoverage
```

## 4. 黄金向量纪律（协议正确性唯一锚）

- `vectors/crypto-vectors.json` 是网关真源（`gtsp-wop-gateway` 仓库 `docs/crypto-vectors.json`）的**只读副本**，**禁止手改**
- `wop-sdk-core` 通过 testResources 将其挂入测试 classpath，本地与 CI 消费同一份
- 新增/变更协议行为的标准流程：
  1. 先改网关仓真源（或从网关重新导出向量）；
  2. 同步副本到本仓 `vectors/`；
  3. 更新全量消费测试（字节级断言），确保新向量被真实消费，不允许"挂上文件但没人断言"
- 负向量（篡改密文、跨套件族材料、错误格式、非严格 base64url 等）必须有对应的"必须拒绝"断言，不允许只测正向路径

## 5. 编码规范

- Java 8 惯例：不可变对象优先、构造器/builder 构造、资源用 try-with-resources；公共 API 以现有 `WopClient` 风格为准，不引入第二套惯例
- **Java 8 语言级禁用清单**（`maven.compiler.release=8` 门禁强制，出现即编译失败）：
  - `record` 声明（值对象用 final class + 全字段 equals/hashCode/toString，数组字段按引用比较以保持 record 等价语义）
  - switch 表达式（`->` 分支 / `yield`）与 switch 模式匹配
  - `var` 局部变量推断、`instanceof` 模式匹配
  - `Map.of` / `List.of` / `Set.of` / `List.copyOf`（用 `Collections.singletonMap` / `Arrays.asList` / `new LinkedHashMap<>()`）
  - `String.repeat` / `String.strip*` / `StringBuilder.isEmpty`（JDK 11+）、`InputStream.readAllBytes`（JDK 9+）、`BigInteger.TWO`（JDK 9+）
  - `URLEncoder.encode(String, Charset)` 重载（JDK 10+）——统一走 `CanonicalRequest.urlencode(String, String charsetName)` seam
  - `java.net.http` 模块（JDK 11+）——HTTP 传输用 `HttpURLConnection`（见 `wop-sdk-jdkhttp`）或 OkHttp/Unirest 适配器
- 模块运行时要求：`wop-sdk-unirest` 依赖 unirest-java-core 4.x（上游字节码 major 55），运行时要求 Java 11+；其 pom profile 在 JDK<11 自动跳过测试，JDK 8 用户请改用 okhttp/jdkhttp 适配器
- 错误契约保持现状：
  - 出向（`buildRequest`）：配置/协议格式错误抛 `WopSdkException`（本地明确、鉴权前可判定）
  - 入向（`verifyResponse`/`verifyCallback`）：统一返回 `VerifyResult`、永不抛异常；签名/解密失败对外模糊（I7，防 oracle）
- 与 spec 功能面对齐，改动前先核对条款落点：

| spec 条款 | 含义 | 本仓落点 |
|-----------|------|----------|
| F1 | 套件解析（`WOP-RSA3072/4096-SHA256`、`WOP-SM2-SM3`） | core 套件注册与推导 |
| F2 | canonicalRequest | core 请求规范化 |
| F3 | `x-wop-sign` 加验签 | core 签名 |
| F4 | `x-wop-content-digest` | core 摘要头（无 body 自动缺席，D2） |
| F5 | L2 数字信封 | core DEK 包装 + bulk 加密 |
| F6 | 入向校验顺序（验签 → digest → DEK 解包 → alg 族比对 → bulk 解密） | core `verifyResponse`/`verifyCallback` |
| F7 | 线上字节格式（严格无填充 base64url、签名 r‖s 64B、C1C3C2 等） | core 编解码 |
| F9 | 防重放（CSPRNG nonce + 时间戳） | core 出向头生成 |
| I7 | 错误模糊化 | core `VerifyResult` |

## 6. 提交规范

Conventional Commits，body 用中文说明动机与影响：

```
<type>(<scope>): <subject>

<中文 body>
```

常用 type：`feat` / `fix` / `test` / `docs` / `chore`（必要时 `refactor` / `build`）。

## 7. PR 流程

- 目标分支：`main`
- CI 必须全绿：全部测试通过 + 覆盖率门禁（≥98%）+ 向量 conformance 套件通过
- 涉协议行为的 PR 必须同时说明对应的网关真源/向量变更（见 §4）
- reviewer 复核通过后合并

## 8. 发布流程

发布由 tag 触发（`.github/workflows/release.yml`）：

1. 版本号同步到全部模块 pom：`mvn versions:set -DnewVersion=X.Y.Z` → `mvn versions:commit`，提交
2. 打 tag 并推送：`git tag vX.Y.Z && git push origin vX.Y.Z`
3. workflow 校验 tag 与 pom 版本一致后，先跑 `mvn -B -ntp verify`（与 CI 相同门禁），全绿后以 `mvn -P release deploy` 上传 Central Portal；autoPublish=false 时构件停在待发布状态，**人工核对后到 Portal 手动 Publish**（首次发版策略，详见 [docs/release-guide.md](docs/release-guide.md)）；失败即中止，不留半发布状态

发布通道为 Sonatype **Maven Central Portal**（OSSRH 已于 2025-06 停服后的官方路径）。

组织级前置条件（一次性，详见 release.yml 头部注释）：
- 在 [Central Portal](https://central.sonatype.com) 注册并验证 namespace `com.wanlianyida`（**经 wanlianyida.com DNS TXT 验证**；GitHub 验证仅适用 io.github.* 形态）
- 生成 Portal 用户令牌 → GitHub Secret `MAVEN_CENTRAL_TOKEN`（格式 `<token-user>:<token-pass>`）
- 发布用 GPG 密钥对（公钥上传 Portal）→ Secrets `GPG_PRIVATE_KEY`、`GPG_PASSPHRASE`

凭证一律走 GitHub Secrets，绝不写入仓库；`release` profile 仅在发布 workflow 中激活，日常构建不受影响。

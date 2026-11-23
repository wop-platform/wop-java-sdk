# Quint 形式化发现：连接超时不在 failover 白名单，可用性缺口

状态：**已修复**（修复方向 1 已于 `022bcee` 落地：`WopSdkException.Phase` 打标 + `isPreSendRetryable` 按阶段判定）。关联 spec：[`failover.qnt`](./failover.qnt)（`failover_current` = 修复前策略，`failover_fixed` = 对照策略）。

## 结论

`FailoverTransport.isPreSendRetryable` 的白名单（`ConnectException` / `UnknownHostException` / `NoRouteToHostException`）覆盖不了**连接超时**：主网关 TCP 握手超时（黑洞、丢包、防火墙 DROP——正是 failover 最该生效的场景）会直接抛给调用方，备用网关不被尝试。连接超时在语义上属"发送前失败"（请求字节未发出，重试无重复副作用），与连接拒绝同类。

## 证据链

### 1. falsifier：Quint 模型反例（已复跑）

最小实例 N=2 候选、budget=1，环境非确定选取，Apalache 穷尽验证（`--max-steps=6`）：

| 模块 | availability | boundedAttempts | noRetryAfterSend | successOnlyWhenUp |
|---|---|---|---|---|
| `failover_current` | **violation** | ok | ok | ok |
| `failover_fixed` | ok | ok | ok | ok |

反例（`quint run --main=failover_current --invariant=availability specs/quint/failover.qnt`）：

```
[State 0] env: [ConnectTimeout, Up], idx: 0, history: [], outcome: running
[State 1] env: [ConnectTimeout, Up], history: [ConnectTimeout], outcome: failed
```

两条策略仅差 `retryable` 一行（是否纳入 `ConnectTimeout`），其余逐行相同；修复版通过全部四条不变量，说明恢复可用性不牺牲"读超时后不得重试"这条安全性。

复现：`quint verify --main=failover_current --invariant=availability --max-steps=6 specs/quint/failover.qnt`（需 `PATH=/opt/homebrew/opt/openjdk@21/bin:$PATH`，quint 0.33.1 + apalache 0.62.4）。

### 2. 原始素材：源码锚点 + 异常类型实测

- `wop-sdk-core/src/main/java/com/wanlianyida/wop/FailoverTransport.java:68`：`isPreSendRetryable` 仅认 `ConnectException`/`UnknownHostException`/`NoRouteToHostException`，其余 `WopSdkException` 原样上抛（:42）。
- `JdkHttpTransport.java:114-115`、`OkHttpTransport.java:81`、`UnirestTransport.java:126`：三适配器均把底层异常包成 `WopSdkException`，不按超时种类分类（全仓 `SocketTimeout` 零命中）。
- 实测（JDK 21，`/tmp/wop-quint-exp/TimeoutProbe.java`，可复跑）：对 RFC5737 黑洞地址 `192.0.2.1:81` 设 1s 连接超时 → `java.net.SocketTimeoutException: Connect timed out`（`instanceof ConnectException = false`）；对本地 accept 后不响应的服务端设 800ms 读超时 → `java.net.SocketTimeoutException: Read timed out`。**两类超时同为 `SocketTimeoutException`**，仅消息字符串不同。

三者合并：连接超时经适配器包成 `WopSdkException(SocketTimeoutException)`，不命中白名单 → 不重试，与模型反例逐点对应。

### 3. 缺证声明

- OkHttp 的连接超时类型已在修复阶段实测（`OkHttpTransportPhaseTest.connectTimeoutReportsConnectPhase`：`SocketTimeoutException`，与 JDK 一致）；Unirest 未实测，仅靠其 cause 链含 `ConnectException` 的类型白名单兜底。
- `successOnlyWhenUp` 依赖 `succeed` 不推进 `idx` 的建模约定，是模型内定义而非对实现的断言。

## 修复（已采纳方向 1，`022bcee`）

区分"是否已发出请求"不能靠异常类型或消息字符串（实测已证不可区分），需要显式 phase 信息。采纳方案：`WopSdkException` 增加 `Phase`（`UNKNOWN`/`CONNECT`/`SENT`），适配器按阶段打标，`isPreSendRetryable` 先看 phase、`UNKNOWN` 才退回异常类型白名单（第三方 Transport 行为不变）。

- jdkhttp：以显式 `HttpURLConnection.connect()` 为唯一边界（其返回后请求体才写出），`setRequestMethod`/`setDoOutput` 相应上移到 connect 之前。
- okhttp：以 network interceptor 为边界——它在 `ConnectInterceptor` 之后执行，连接/DNS/TLS 失败时不触发，读超时与写体失败时已置 `SENT`。
- Unirest：未改码。其 `java.net.http` 后端的连接超时 cause 链最内层为 `java.net.ConnectException: HTTP connect timed out`，现有类型白名单本就命中；且模块 `maven.compiler.release=8` 无法编译期引用 `java.net.http.*`。该正确性依赖上游异常类型，属脆弱点，上游改为裸 `HttpTimeoutException` 时会退化为不重试（安全侧）。

落地时发现两处原方案未预见的约束：jdkhttp 的 `setRequestMethod` 必须在 `connect()` 前调用；okhttp 用应用拦截器无法区分（它在 `RetryAndFollowUp` 之前，早于建连），必须用 network interceptor。

行为变化：TLS 握手失败此前不重试，打标后归 `CONNECT` 变为可重试（请求字节未发出，无重复副作用）。

## 未采纳的替代方案

2. `TransportCall` 返回侧增加连接阶段回调（适配器在 `connect()` 前后通知），core 据此判定；不动异常契约但要改 `Transport` SPI，且 phase 仍需沿调用栈传递——收益低于方案 1。
3. 不改 SDK，文档建议用户配置备用网关 + 缩短 connectTimeout（现状缓解，不解决）。

## 附带观察（不展开）

- OkHttp 适配器未显式关闭 `retryOnConnectionFailure`（默认 true，OkHttp 自己会静默重试连接失败），与 `FailoverTransport` 的计数语义叠加。已实测（前序会话）确认：仅在同 host 多 A 记录时成立，单 IP 下 `retry` 取 true/false 完全一致，跨网关绝不发生；只会把单次 attempt 的耗时上限抬到「DNS 路由数 × connectTimeout」。故不改 `defaultClient()`——关掉它会削弱单网关场景下的韧性，而收益为零。`docs/fault-injection-playbook.md:24` 已要求故障注入用例关闭它。
- 请求级 `serverRoot` 覆盖会把候选收敛为单点（`WopRequestContext` 覆盖分支），failover 与请求级覆盖互斥，属有意设计（§7.3），本模型未覆盖。

## 不做什么

- 不把 `quint` 接入 CI / lefthook（本地工具链，CI 引入是独立决策）。
- 不关闭 OkHttp `retryOnConnectionFailure`（见上，实测收益为零且有损）。
- 不给 `WopSdkException` 显式钉 `serialVersionUID`：默认 UID 会随公共成员变化而变，序列化兼容性由 japicmp 报出并在发布说明披露；本类非长期序列化载体。

# Quint 形式化发现：连接超时不在 failover 白名单，可用性缺口

状态：发现报告（未决策）。关联 spec：[`failover.qnt`](./failover.qnt)（`failover_current` = 现状策略，`failover_fixed` = 对照策略）。

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

- OkHttp / Unirest 的连接超时异常类型未实测（推断自其 catch 块与公开行为）；对结论无影响——两个适配器同样只产 `WopSdkException`，白名单判定在 core，适配器怎么抛都不在白名单内。
- `successOnlyWhenUp` 依赖 `succeed` 不推进 `idx` 的建模约定，是模型内定义而非对实现的断言。

## 修复方向（涉及接口变更，需裁决后才动）

区分"是否已发出请求"不能靠异常类型或消息字符串（实测已证不可区分），需要显式 phase 信息，候选：

1. `WopSdkException` 增加 `phase`（PRE_CONNECT / CONNECT / POST_SEND）字段，适配器在连接阶段失败时标注；core 按 phase 判定可重试。改公共异常类，japicmp 门禁会拦，需同 PR 刷新 baseline 并走破坏性评估。
2. `TransportCall` 返回侧增加连接阶段回调（适配器在 `connect()` 前后通知），core 据此判定；不动异常契约但改 `Transport` SPI。
3. 不改 SDK，文档建议用户配置备用网关 + 缩短 connectTimeout（现状缓解，不解决）。

## 附带观察（不展开）

- OkHttp 适配器未显式关闭 `retryOnConnectionFailure`（默认 true，OkHttp 自己会静默重试连接失败），与 `FailoverTransport` 的计数语义叠加；`docs/fault-injection-playbook.md:24` 已要求故障注入用例关闭它。
- 请求级 `serverRoot` 覆盖会把候选收敛为单点（`WopRequestContext` 覆盖分支），failover 与请求级覆盖互斥，属有意设计（§7.3），本模型未覆盖。

## 不做什么

- 不改任何实现代码（修复属接口/契约变更，待裁决）。
- 不接 CI / lefthook（`quint` 为本地工具链，CI 引入是独立决策）。

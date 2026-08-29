# WOP SDK 故障注入测试手册（六语言通用 Playbook）

> 版本：1.0（2026-08-29，源自 wop-java-sdk 实测场景；`FaultInjectionTest` / `OkHttpTransportFaultInjectionTest` / `JdkHttpTransportFaultInjectionTest`）
> 适用：wop-{go,typescript,python,php,dotnet}-sdk 各仓；协议依据 crypto-strategy-spec v0.3（D2/F6/I7/10.2）
> 纪律：**先写测试看它对未注入的实现通过（绿），再注入故障看它拒绝（红）**——与 TDD 红→绿同构；每条场景必须断言到"错误分类"，不只是"抛异常"

## 0. 判定基线（每条断言的唯一锚）

| 判定性质 | 对外语义 | 断言要点 |
|---|---|---|
| **公开结构可判定**（信封 JSON 形态、头格式、长度、标签族） | **明确**（10.2 解析/支持/一致性类） | 错误消息可区分、可含细节 |
| **密钥参与才可判定**（AEAD tag、解包、验签字节比对） | **模糊**（I7） | 错误文案恒定（"签名验证失败"/"解密失败"），无任何区分细节 |

**核心测试设计**：构造"格式全部合法、仅密钥参与层被破坏"的载体，断言它落模糊类；
构造"结构层就坏"的载体，断言它落明确类——两条对照钉死 I7 分界。

## 1. 协议层注入矩阵（7 条，全部必做）

前提：测试内先按协议**正向拼装**一份完全合法的响应/回调（测试侧镜像平台角色：
平台私钥加签、商户公钥包 DEK），再对单一变量注入。digest 与签名**按注入后的载体重算**
（否则先死在摘要层，到不了目标层——这是本手册最容易犯的错）。

| # | 注入 | 构造方式 | 期望（Reason 类） | 断言 |
|---|------|----------|------------------|------|
| P1 | 信封密文单字符损伤 | wire `{"encrypted":"..."}` 内翻转 1 个 base64url 字符（保长度/字母表合法），重算 digest+签名 | **DECRYPT_FAILED（模糊）** | 文案恒定无细节 |
| P2 | 传输截断 | 去掉 wire 最后 1 字节（砍掉 `}`），重算 digest+签名 | **INVALID_ENCRYPTED_BODY（明确）** | 与 P1 构成分界对照 |
| P3 | DEK 载荷 key 段畸形 | 解包合法、alg 正确，但 key 长度错（如 AES 31B） | **DECRYPT_FAILED（模糊）** | bulk 解密抛错归模糊 |
| P4 | 响应声明跨族套件 | 头声明 `WOP-SM2-SM3`，签名值/密钥实为 RSA | **SIGNATURE_FAILED（模糊）** | 不泄露"密钥族不符"细节 |
| P5 | 跨端点签名重放 | 签名覆盖 `/gateway/pay`，用 `/gateway/refund` 校验 | **SIGNATURE_FAILED** | 原路径同体校验仍通过（自证非构造错误） |
| P6 | 签名段 URL 编码污染 | 签名尾追加 `%3D`（模拟中间层 urlencode） | **SIGNATURE_FAILED（模糊）** | 严格 base64url 拒 `=` |
| P7 | 入向头名大小写混合 | 非官方栈送 `X-WOP-SIGN` 等混合形态 | **ok（通过）** | 核心层大小写不敏感兜底 |

## 2. 网络层注入矩阵（适配器，每语言必做）

| # | 注入 | 期望 | 各语言工具 |
|---|------|------|-----------|
| N1 | 连接拒收（未监听端口） | 传输异常包装为本 SDK 明确异常（系统类） | 任意 |
| N2 | 连接超时（不可路由地址 + 短超时） | 包装异常 + **秒级返回**（断言耗时） | 见 §3 各栈 timeout 注入 |
| N3 | 响应体中途断连 | IOException 族包装 | okhttp `SocketPolicy.DISCONNECT_DURING_RESPONSE_BODY`；Go `httptest` + `Flusher` 后 `Close`；TS msw `closeSocket()`/nock `socketDelay`；Python 自管 handler 提前 return；PHP Guzzle mock 置短 `stream`；.NET 自管 handler 提前 abort |
| N4 | 5xx 状态透传 | `TransportResponse.statusCode` 原样返回，适配器**不做**状态语义 | 各 mock 服务均可 |
| N5 | 响应头名规范化 | 送 `X-Wop-Sign`，取 `x-wop-sign` 得同值；**存储键恒小写** | 断言 keySet 全小写或等价 |
| N6 | 204/无实体 | body 映射为空字节/空串（verify 层按无 body 处理，D2） | 各 mock 服务均可 |

选做（环境允许时）：读超时（延迟响应+短读超时）、TLS 指向明文端口（**须禁用静默重试**，
见 §4 教训）。

## 3. 各语言落点提示

| 语言 | 请求/响应 mock | 网络层故障 | 已有参考 |
|------|---------------|-----------|----------|
| Java | MockWebServer（okhttp 模块）/ com.sun.net.httpserver（jdkhttp 模块） | SocketPolicy / 短超时 client | 本仓三个 *FaultInjectionTest |
| Go | net/http/httptest.Server | handler 内 `panic(http.ErrAbortHandler)` 模拟断流；`httptest.NewUnstartedServer` 不 Start 模拟拒连 | spec §3 语句覆盖+分支清单 |
| TypeScript | nock（拦截+故障）或 msw（`closeSocket`/error resolver）；Node 原生 `http.createServer` 最稳 | nock `delayConnection`/`socketDelay`/replyWithError | vitest |
| Python | pytest + 自管 `http.server` 线程 / aiohttp test_utils；responses 库做头/状态注入 | handler 提前关闭连接；`requests` 侧 `ConnectionError` 断言 | pytest |
| PHP | Guzzle `MockHandler`+`RequestException`；本地 `php -S` 做真网络 | MockHandler 抛 `ConnectException`；真实 socket 用 stream context 超时 | PHPUnit |
| .NET | 自管 `HttpListener`/kestrel 测试主机 | handler 中 `context.Abort()`；`HttpClient.Timeout` 短值 | xUnit |

## 4. 环境稳定性教训（Java 实测踩坑，各语言同样适用）

1. **系统代理会劫持"不可路由地址"**：JDK HttpClient 默认走 `ProxySelector`，对
   `10.255.255.1` 的"连接超时"会变成"经代理 10s 后正常返回"，测试假绿/假慢。
   → 超时类用例优先用"未监听端口拒连"（确定性），不可路由地址超时只作选做，或显式禁代理。
2. **HTTP 客户端默认静默重试**：OkHttp `retryOnConnectionFailure=true` 会把 TLS 错配
   故障拖到 10s 重试链走完。→ 故障注入用例必须用**禁重试+短超时**的专属 client 实例。
3. **digest/签名必须对"注入后"的载体重算**：篡改密文后若不重算 digest，校验会死在
   摘要层，永远到不了 AEAD/解包层——故障注入就白写了（Java 版 P1 首版即犯此错）。
4. **故障注入的目标是"层"不是"点"**：同是"响应坏了"，截断（结构层→明确）与密文损伤
   （密钥层→模糊）必须成对出现，否则 I7 分界没有被测试钉死。

## 5. 验收口径

- 上述 P1–P7、N1–N6 每条至少一个用例，断言到错误分类/文案（不允许只断言"抛异常"）
- 全部纳入 CI（与向量 conformance 同一道 `test` 命令跑），不允许 `@Ignore`/`skip` 长期存在
- 手册场景与各语言覆盖率门禁互相独立：故障注入不是覆盖率的替代，是**错误传播语义**的合同

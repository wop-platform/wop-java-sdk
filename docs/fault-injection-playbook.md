# WOP SDK 故障注入测试手册（Java 仓消费指引）

> **组织级真源**：[wop-specs/docs/fault-injection-playbook.md](https://github.com/wop-platform/wop-specs/blob/main/docs/fault-injection-playbook.md)
> （P1–P7 协议层矩阵、N1–N6 网络层矩阵、I7 分界判定基线与验收口径以真源为准，本仓不再维护副本）。
> 本文件仅保留 Java 仓落点与实测注记。

## 本仓落点

| 层 | 用例位置 | mock 栈 |
|---|---|---|
| 协议层 P1–P7 | `wop-sdk-core` `FaultInjectionTest` | 测试内镜像平台角色正向拼装 + 单变量注入 |
| 网络层 N1–N6（okhttp） | `wop-sdk-okhttp` `OkHttpTransportFaultInjectionTest` | MockWebServer（SocketPolicy / 短超时专属 client） |
| 网络层 N1–N6（jdkhttp） | `wop-sdk-jdkhttp` `JdkHttpTransportFaultInjectionTest` | com.sun.net.httpserver 自管 handler |

## Java 仓实测注记（真源 §4 的本仓补充）

1. **分类基线随 interop 合同更新（2026-08-29 拉齐）**：P6（签名段 URL 编码污染，携带
   `=`/`%3D` 等 b64url 非法结构）为**公开结构知识 → 协议类明确拒绝**
   （`VerifyResult.Reason.INVALID_SIGN_HEADER`，格式类错误码），非验签模糊；
   P4 同族（响应声明套件与商户配置不符）亦为协议类明确拒绝（`SUITE_MISMATCH`）。
   依据：wop-specs `interop/v1` 错误分类合同（n06/n11）。
2. JDK HttpClient 默认经 `ProxySelector` 走系统代理，"不可路由地址超时"会被代理劫持成正常返回
   ——超时类用例优先用未监听端口拒连，或显式禁代理（真源 §4.1 的 Java 实测出处即本仓）。
3. OkHttp `retryOnConnectionFailure=true` 默认静默重试会拖长故障注入链路——故障注入用例
   必须使用禁重试+短超时的专属 client 实例（真源 §4.2 出处即本仓）。
4. interop 静态负样本（n01–n16，含 P1/P2/P3/P5/P6/P7 的冻结等价样本）由
   `InteropConformanceTest` 按样本集合同消费，与手册注入用例互补。

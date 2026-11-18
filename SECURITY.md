# 安全策略

## 支持的版本

| 发行线 | 版本示例 | 状态 |
|---|---|---|
| jdk18on（`main`） | `0.3.x` | 正常维护，接收安全修复 |
| jdk15on（`release/jdk15on-*`） | `0.3.0-jdk15on.x` | 过渡发行线，尽力修复；底层 BC 已停止维护 |

15on 线使用 `bcprov-jdk15on` 1.70（该 artifact 的最后一版，2021-12）。此后
BouncyCastle 的安全修复只进入 `bcprov-jdk18on` 分支，1.70 不会获得回灌补丁。
两条线的差异与选择方法见 [docs/release-lines.md](docs/release-lines.md)。

## 上报漏洞

请**不要**通过公开 issue 披露未修复的安全问题。使用 GitHub 仓库的
**Security → Report a vulnerability** 私密上报，并尽量包含：

- 受影响版本与发行线（`mvn dependency:tree -Dincludes=org.bouncycastle` 输出）；
- 最小复现步骤或 PoC（不要附带真实密钥、证书或生产数据）；
- 影响评估（机密性 / 完整性 / 可用性）。

我们会在确认后同步修复计划；需要协调披露时，请在报告中说明期望的时间线。

## 不在范围内

- 消费者自行替换或排除 SDK 依赖后产生的组合问题；
- 消费者 classpath 上同时存在 `bcprov-jdk15on` 与 `bcprov-jdk18on` 的配置错误
  （这属于依赖冲突，不是 SDK 漏洞）；
- 已停止维护的 15on 线中、且仅存在于 EOL BouncyCastle 1.70 自身的问题——
  此类问题应推动迁移到 18on 线。

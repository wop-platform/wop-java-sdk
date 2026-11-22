<!-- 由 2026-11-21 注释清扫生成: excuse 桶聚合的 hack 修复欠账草稿, 逐条人工确认后转工单 -->

# wop-java-sdk — excuse 桶 4 块复核（登记 + 裁决）

扫描器把下列 4 条注释归入 `excuse`（"为坏代码找借口"类），关键词命中「兜底 / 临时 / 防御」。
逐条人工复核结论：**4/4 均为误报（false positive），建议保留，无需修复。**
理由共同点：这些「兜底」不是给遗留缺陷开脱，而是在**陈述协议/语言约束下的必要分支及其 why**（大小写不敏感的入向头、Java 8 无 switch 表达式的穷尽封闭、SPI 三态测试夹具构造），属于本仓价值最高的一类注释（decision），删掉会丢失协议与语言基线约束。

---

## 1. `f6eac953a95e` — FaultInjectionTest.java:216
```
// 故障形态：非官方适配器送来大小写混合头名——core 层大小写不敏感兜底
```
- 分类：**误报**。这里描述的是**被测行为本身**（HTTP 头名大小写不敏感，core 需对混合大小写头名归一），而不是为某个临时实现辩护。
- 价值：与 `bca16d33ae9d`（头名小写不敏感）互为镜像；说明该测试为什么必须用非官方适配器注入，删掉后读者无法判断这是"缺陷绕过"还是"合同要求"。
- 处置：保留。无需 issue。

## 2. `079af11fdf1f` + `3.` `59196e4f8b73` — InteropConformanceTest.java:125 / :127
```
// Java 8 无 switch 表达式：经典 switch 全枚举 case + 末尾抛错兜底，
// switch 语句不像 switch 表达式那样编译期穷尽检查，故以显式兜底封闭）。
```
- 分类：**误报（两行为同一条注释的续行）**。这是 JDK 8 基线约束的记录：switch 表达式（JDK 14+）不可用，switch 语句无编译期穷尽性检查，因此必须手写 default 抛错来封闭枚举。属于典型的「why 而非 what」。
- 价值：本仓以 Java 8 为兼容基线（同族注释见 `a5dece53accd`、`15eb2d7f0db2`、`0450c31cbd7e`、`84128c990d33`），这类注释是基线约束的唯一书面依据。
- 处置：保留（两行合并视为一条）。无需 issue。

## 4. `c641f04b0249` — TransportFactoryDiscoveryTest.java:19
```
/** TransportFactory SPI 发现三态（config-spec §2.2/K18，§13.1 测试点 1）：
 *  恰一即用、零/多 fail-fast、注册项损坏包装为 WopError.configuration。
 *  core 测试 classpath 经 META-INF/services 恰注册一个测试 factory（alpha）构造「恰一」态；
 *  「零」态用 parent=null 的隔离 URLClassLoader（仅 core 类目录，无注册文件）；
 *  「多」态与损坏态用临时 services 目录叠加测试 classpath（同名注册由 ServiceLoader 去重）。 */
```
- 分类：**误报**。命中词应为「临时 services 目录」，但此处「临时」指测试夹具的临时目录，不是"临时方案"。
- 价值：说明三种 SPI 态**如何被构造出来**（隔离 loader / 叠加 services），是理解该测试可信度的前提，也解释了为何零态必须 parent=null。
- 处置：保留。无需 issue。

---

## 汇总

| id | 文件:行 | 裁决 | 关键词误命中 |
|---|---|---|---|
| `f6eac953a95e` | FaultInjectionTest.java:216 | 误报，保留 | 兜底 |
| `079af11fdf1f` | InteropConformanceTest.java:125 | 误报，保留 | 兜底 |
| `59196e4f8b73` | InteropConformanceTest.java:127 | 误报，保留 | 兜底 |
| `c641f04b0249` | TransportFactoryDiscoveryTest.java:19 | 误报，保留 | 临时 |

excuse 桶误报率 4/4 = 100%。建议：扫描器对「兜底 / 临时 / 防御」做关键词过滤时，需排除后接「Java 8 / 编译期穷尽 / 大小写不敏感 / services 目录」等约束陈述的上下文，否则对外协议 SDK 会系统性误删最高价值的基线约束注释。

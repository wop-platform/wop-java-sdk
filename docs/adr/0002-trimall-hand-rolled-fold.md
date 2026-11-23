# ADR: trimall 改手写扫描折叠（去掉 replaceAll 正则）

- 状态: Accepted（PR #53）
- 基线: `3af75c9`
- 范围: `wop-sdk-core/src/main/java/com/wanlianyida/wop/crypto/CanonicalRequest.java` 的 `trimall`

## 背景与裁决

`trimall` 旧实现 `text.trim().replaceAll("\\s+", " ")`，每次调用编译 `Pattern` 并分配 `Matcher`。
`canonicalHeaders` 对每个标头的名与值各调一次，5 标头请求固定 10 次调用，属签名单请求的纯开销。

**裁决**：折叠改为手写扫描（分配策略见下节「两遍扫描」），两级判定保持分离——

- 首尾裁剪沿用 `String.trim()` 的 `<= ' '` 口径（含 0x00–0x1F 全部控制字符）；
- 中间折叠只认 `\s` 的 6 个 ASCII 空白（空格、`\t`、`\n`、`\u000B`、`\f`、`\r`），其余控制字符原样保留。

两级口径不能合并成「统一按 `<= ' '` 折叠」：那会改变 0x00–0x1F 非空白控制字符与跨段落的输出，
破坏与网关 `CanonicalRequestBuilder` 的逐字节对齐（spec §1.3）。

**不做**：不改 `urlencode`、不改 `canonicalHeaders` 的排序与拼接；不引入 `Pattern` 静态缓存
（缓存版仍需 `Matcher` 分配，且新增可变共享状态）。

### 折叠的分配策略（两遍扫描）

首版按 `trimmed.length()` 一次性预分配 `StringBuilder`，PR #53 评审指出该容量按**未折叠**全长
预留，攻击者可构造「短 token + 超长内部空白」的未认证签名头让单次回调按输入长度分配堆。
`verifyInbound` 在验签前先重建 canonical request，故该分配发生在认证之前。

**裁决**：改为两遍扫描——第一遍只计数得折叠后长度 `folded`，同时判定是否需要重写；
无需重写时直接返回 `trimmed`（零分配），否则按 `folded` 精确分配后第二遍填充。

快路径判据不能写成「折叠后长度 == 原长度」：`"a\tb"` 折叠后长度不变但内容不同（`\t`→空格），
必须显式判定「出现非空格的可折叠空白，或出现连续两个及以上可折叠空白」。

**不做**：不给容量加上限常量（如 4096）。上限在「超长单 token 无空白」形状上反而触发
`StringBuilder` 扩容复制，实测分配 1.47×、时间无收益，且引入与语义无关的魔法数。

## 证据

### 1. JMH 复测（本机 JDK 17.0.21，Apple Silicon）

基准类 `wop-sdk-core/src/test/java/com/wanlianyida/wop/crypto/bench/TrimallBenchmark`，
`@Warmup(3×1s) @Measurement(5×1s) @Fork(2)`，新旧实现同轮同 JVM 对照（旧实现作为 oracle 留在基准类内）。
复跑：

```bash
mvn -o -pl wop-sdk-core test-compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp wop-sdk-core/target/classes:wop-sdk-core/target/test-classes:$(cat wop-sdk-core/target/cp.txt) \
     org.openjdk.jmh.Main 'TrimallBenchmark' -foe true
```

JDK 23+ 默认关闭隐式注解处理，需加 `-Dmaven.compiler.proc=full` 才会生成 `META-INF/BenchmarkList`
（缺它时 JMH 报 "No benchmarks"）；只影响手工复跑，不影响 `mvn test`/`verify`。

下表为两遍扫描版（`trimallCurrent`）对旧正则（`trimallLegacy`）的同轮对照（`-rf json` 输出，`Cnt=10`）：

| 基准（`text` 参数） | 旧正则 ns/op | 两遍扫描 ns/op | 降幅 |
|---|---|---|---|
| trimall `x-wop-timestamp`（无空白） | 66.51 ± 4.00 | 12.92 ± 0.83 | −81% |
| trimall ` 1758900000000 `（首尾空白） | 74.94 ± 2.72 | 15.36 ± 1.54 | −80% |
| trimall `sha-256   4cf7\t9a2e`（内嵌多空白） | 131.14 ± 3.07 | 46.52 ± 1.34 | −65% |
| canonicalHeaders（5 标头） | 1572–1682 | 792–794 | −50%…−53% |

单遍预分配版（首版，已废弃）的数字来自同一 JMH 配置下的仓外变体实验（45.4/27.4/45.9 ns、headers 1017–1070 ns），
该变体未留在仓内，故不可由上面的命令直接复现；保留它只为说明改动的净效果：
两遍扫描在无折叠与首尾空白两形状上相对单遍版再降 2–3×，内嵌多空白持平，
「超长双空格值 `WOP-RSA2048-SHA256  v1/1800/a/b`」略慢（74.07 vs 50.99，但仍优于旧正则 199.43）。

### 2. 分配量对照（评审意见的直接证据）

`com.sun.management.ThreadMXBean#getCurrentThreadAllocatedBytes` 逐调用测分配字节数
（预热 500 次后取 500 次均值，JDK 17 默认 GC）。

| 输入形状 | 首版预分配 B/op | 两遍扫描 B/op | 旧正则 B/op |
|---|---|---|---|
| 真实标头 `"x-wop-timestamp"` / `"app_001"` / `"sha-256 4cf7"` | 96–112 | 0 | 736–904 |
| 真实标头 `" 1758900000000 "` | 168 | 56 | 792 |
| 真实标头 `"WOP-RSA2048-SHA256  v1/1800/a/b"` | 144 | 144 | 976 |
| 对抗 `'x'` + 全空白 + `'x'`，1 KiB | 1 112 | 96 | 896 |
| 同上 64 KiB | 65 624 | 96 | 896 |
| 同上 1 MiB | 1 048 664 | 96 | 896 |

两遍扫描的分配量是 O(折叠后长度) 而非 O(输入长度)：单段超长空白形状下恒为 96 B，比旧正则的 896 B 低 9×；
首版预分配则随输入线性增长（1 MiB 输入 ≈1 MiB 分配），即评审所指的放大面。
无折叠输入走快路径返回原串，零分配。（密集交替的 `'x'`+7 空白形状折叠后仍有输入长度的 1/4，
两遍扫描分配为旧正则的 0.17×，仍是同向改善。）

`cap4096` 变体被否的依据：对抗形状 4 184 B（优于首版，劣于两遍扫描）；
「超长单 token 无空白」形状 131 128 → 192 696 B（1.47×，容量上限触发扩容复制）。

### 3. 等价性 falsifier

`CanonicalRequestTest#trimallIsEquivalentToLegacyRegexOracle` 以旧正则实现为独立 oracle
差分复算 19 组输入（含 `\u0000`/`\u0001`/`\u0007`/`\u000B`/`\f`、首尾与内嵌、全空白、空串、中文）。
另有 `trimallFoldsOnlyAsciiRegexWhitespace` 钉住两级口径的分离点。任一语义漂移即红。

两遍改写另做了一次仓外差分：以旧正则实现为 oracle，随机生成 30 万条长度 0–13、
字符池覆盖 6 个可折叠空白与 `\u0000`/`\u0001`/`\u0007`/`\u001F`/`\u00A0`/全角空格/中文的输入，
逐条比对输出，mismatches = 0。仓内用 `trimallReturnsInputUnchangedWhenAlreadyCanonical`
（快路径返回同一实例）与 `trimallRewritesOnlyWhenFoldChangesBytes`（`"a\tb"` 长度不变但须重写）
钉住两条分支。

**反证条件**：若上游 spec 把 trimall 口径改为 Unicode `\s`（含 NBSP/全角空格）或改为统一 `<= ' '` 折叠，
本决策失效，须重写实现与 oracle。

### 4. 门禁复核

- JaCoCo BUNDLE LINE/BRANCH 100%：`mvn -o -pl wop-sdk-core verify` 全绿（469 tests）；
  `CanonicalRequest` 自身 LINE 52/52、BRANCH 60/60。
- japicmp：无公共 API 面变化（首版引入 `private static isFoldableSpace` 触发 `MODIFIED CLASS`，
  已内联消除，未刷新 API 基线快照）。
- 变异锚点：`scripts/mutation-check.py` 的 CanonicalRequest 锚点只覆盖 `build()` 的 `"\n"`，
  trimall 未被锚定，`check-equivalent-anchors.py` 不受影响。
- PIT：`pitest-maven mutationCoverage` 全模块 `Generated 1195 mutations Killed 1149 (96%)`，阈值 90 通过；
  `CanonicalRequest` 40 个变异 KILLED 39，存活 1 个在 `trimall` 第一遍的 `folded++`（`IncrementsMutator`）——
  该变量只作 `StringBuilder` 初始容量，`StringBuilder` 自动扩容使改小后输出不变，属不可观测的等价变异，
  无法用断言杀死，也不影响模块阈值。

## 收益上限

trimall 在签名单请求里只占总耗时 ≈0.02–0.2%（RSA-2048 签名 ≈582µs 占 ≈97%）。
本次改动是零风险的固定开销削减，不改变性能量级——**如需数量级收益，只能动 RSA 签名路径**，
不在本 ADR 范围。

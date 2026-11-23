# ADR: trimall 改手写扫描折叠（去掉 replaceAll 正则）

- 状态: Proposed（待 PR 评审）
- 基线: `3af75c9`
- 范围: `wop-sdk-core/src/main/java/com/wanlianyida/wop/crypto/CanonicalRequest.java` 的 `trimall`

## 背景与裁决

`trimall` 旧实现 `text.trim().replaceAll("\\s+", " ")`，每次调用编译 `Pattern` 并分配 `Matcher`。
`canonicalHeaders` 对每个标头的名与值各调一次，5 标头请求固定 10 次调用，属签名单请求的纯开销。

**裁决**：折叠改为手写单遍扫描，两级判定保持分离——

- 首尾裁剪沿用 `String.trim()` 的 `<= ' '` 口径（含 0x00–0x1F 全部控制字符）；
- 中间折叠只认 `\s` 的 6 个 ASCII 空白（空格、`\t`、`\n`、`\u000B`、`\f`、`\r`），其余控制字符原样保留。

两级口径不能合并成「统一按 `<= ' '` 折叠」：那会改变 0x00–0x1F 非空白控制字符与跨段落的输出，
破坏与网关 `CanonicalRequestBuilder` 的逐字节对齐（spec §1.3）。

**不做**：不改 `urlencode`、不改 `canonicalHeaders` 的排序与拼接；不引入 `Pattern` 静态缓存
（缓存版仍需 `Matcher` 分配，且新增可变共享状态）。

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

| 基准（`text` 参数） | 旧实现 ns/op | 新实现 ns/op | 降幅 |
|---|---|---|---|
| trimall（无空白 `x-wop-timestamp`） | 69.888 ± 3.560 | 46.183 ± 1.634 | −34% |
| trimall（首尾空白 ` 1758900000000 `） | 70.205 ± 1.867 | 30.990 ± 2.734 | −56% |
| trimall（内嵌多空白+制表符） | 146.159 ± 0.787 | 47.549 ± 2.754 | −67% |
| canonicalHeaders（5 标头） | 1782–1985 | 924–992 | −46%…−50% |

### 2. 等价性 falsifier

`CanonicalRequestTest#trimallIsEquivalentToLegacyRegexOracle` 以旧正则实现为独立 oracle
差分复算 19 组输入（含 `\u0000`/`\u0001`/`\u0007`/`\u000B`/`\f`、首尾与内嵌、全空白、空串、中文）。
另有 `trimallFoldsOnlyAsciiRegexWhitespace` 钉住两级口径的分离点。任一语义漂移即红。

**反证条件**：若上游 spec 把 trimall 口径改为 Unicode `\s`（含 NBSP/全角空格）或改为统一 `<= ' '` 折叠，
本决策失效，须重写实现与 oracle。

### 3. 门禁复核

- JaCoCo BUNDLE LINE/BRANCH 100%：`mvn -o -pl wop-sdk-core verify` 全绿（467 tests）。
- japicmp：无公共 API 面变化（首版引入 `private static isFoldableSpace` 触发 `MODIFIED CLASS`，
  已内联消除，未刷新 API 基线快照）。
- 变异锚点：`scripts/mutation-check.py` 的 CanonicalRequest 锚点只覆盖 `build()` 的 `"\n"`，
  trimall 未被锚定，`check-equivalent-anchors.py` 不受影响。
- PIT：`pitest-maven mutationCoverage` 全模块 1180 变异 KILLED 1135（96%，阈值 90）；
  `CanonicalRequest` 25 个变异全部 KILLED，手写折叠循环不引入存活变异。

## 收益上限

trimall 在签名单请求里只占总耗时 ≈0.02–0.2%（RSA-2048 签名 ≈582µs 占 ≈97%）。
本次改动是零风险的固定开销削减，不改变性能量级——**如需数量级收益，只能动 RSA 签名路径**，
不在本 ADR 范围。

# 发行线（jdk15on / jdk18on）

本仓库对外提供两条 BouncyCastle 依赖线。两条线**代码同源、二进制行为一致**，唯一差异是
BC 的 Maven 坐标；它们**不能出现在同一个 classpath**（`bcprov-jdk15on` 与 `bcprov-jdk18on`
是不同 artifact，但包含同名 `org.bouncycastle.*` 包，同名类随机取胜）。

## 如何选择

```bash
mvn dependency:tree -Dincludes=org.bouncycastle
```

| 依赖树结果 | 选择 | 坐标示例 |
|---|---|---|
| 无 BouncyCastle | 18on 线（`main`） | `0.3.0` |
| `bcprov-jdk18on` | 18on 线（`main`） | `0.3.0` |
| `bcprov-jdk15on`（≥1.65） | 15on 线 | `0.3.0-jdk15on.1` |
| `bcprov-jdk15on`（<1.65） | 先升级 BC，再选 15on 线 | — |

15on 线由 `BouncyCastleVersionGuard` 在运行时校验版本，低于 1.65 会抛
`WopError`（`category=configuration`）并给出升级提示。

## 为什么不能"自动升级"

Maven 版本排序中 `0.3.0-jdk15on.1 < 0.3.0`。Renovate / Dependabot /
`mvn versions:display-dependency-updates` 会把 18on 线的 `0.3.0` 视为可用升级，
接受后消费者的 classpath 上会同时出现两个 BC jar，重新触发本仓库要解决的冲突。

**使用 15on 线时，必须锁定精确版本并限制更新工具。**

Renovate：

```json
{
  "packageRules": [
    {
      "matchPackageNames": [
        "com.wanlianyida:wop-sdk-core",
        "com.wanlianyida:wop-sdk-jdkhttp",
        "com.wanlianyida:wop-sdk-okhttp",
        "com.wanlianyida:wop-sdk-unirest"
      ],
      "allowedVersions": "/^0\\.3\\.0-jdk15on\\.\\d+$/"
    }
  ]
}
```

Dependabot：

```yaml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    ignore:
      # 18on 线的版本，按主干实际发布逐个补充
      - dependency-name: "com.wanlianyida:wop-sdk-core"
        versions: ["0.3.0"]
```

不论使用哪种工具，都建议在 pom 中写死精确版本（不要用范围），并在升级 PR 中检查
`dependency:tree` 是否仍只有一个 `bcprov-*`。

## 维护者约定

1. **版本格式**：`<基线版本>-jdk15on.<序号>`，序号从 1 递增；同一基线只发布一次，不可覆盖。
2. **发布**：`tag = v<完整版本>`，与根 pom 一致（`release.yml` 会校验）；发布前跑
   `mvn -B -ntp verify`，覆盖率与 japicmp 门禁必须全绿。
3. **BC 升级**：15on 分支已冻结在 1.70（最后一版）。若确需变更，必须同步更新
   `BouncyCastleVersionGuard.MIN_VERSION`、CI 兼容矩阵与 README 的适用版本。
4. **不要合回 main**：15on 分支的 BC 坐标变更是发行线差异，不是可合并的功能提交。
5. **变更同步**：15on 线只接受安全修复与兼容性修复；功能开发仍以 `main` 为准，
   需要时手工 cherry-pick 并单独发版。

## 安全边界

`bcprov-jdk15on` 的最后一个版本是 1.70（2021-12）。此后 BouncyCastle 只在
`bcprov-jdk18on` 分支修复安全问题，**1.70 不会获得回灌补丁**。

- 15on 线定位为存量项目的过渡发行线，不承诺长期安全维护；
- 新项目应使用 18on 线；
- 上报渠道与处理流程见仓库根目录 [SECURITY.md](../SECURITY.md)。

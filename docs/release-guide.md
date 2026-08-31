# WOP Java SDK 首次发版操作手册（v0.1.0 → Maven Central）

> 版本：1.0（2026-08-29）｜ 适用：wop-java-sdk 0.1.0 首次发布
> 决策记录：namespace = `com.wanlianyida`（**DNS TXT 验证**，依赖 wanlianyida.com 域名控制权）；
> 首次发布策略 = **autoPublish=false**（上传后人工核对再手动 Publish）
> 概览见 [CONTRIBUTING.md §8](../CONTRIBUTING.md)；自动化细节见 `.github/workflows/release.yml` 头部注释

## 0. 发版前检查结论（已完成，2026-08-29 实测）

| 检查项 | 状态 | 证据 |
|---|---|---|
| 构建链 | ✅ | `mvn -P release -DskipTests package` 预验通过，三模块 sources/javadoc jar 共 6 个全部生成 |
| 坐标 | ✅ | 父/子 pom 全部 `com.wanlianyida`，无 `com.wopplatform` 残留 |
| Central 元数据 | ✅ | name/description/url/licenses/developers/scm 齐备（Central 校验必备） |
| release profile | ✅ | maven-source 3.4.0 / javadoc 3.12.0（doclint=none）/ gpg 3.2.8（loopback）/ central-publishing 0.11.0（autoPublish=false） |
| release.yml | ✅ | tag↔pom 版本一致性校验 → GPG 导入 → Secrets 注入 settings.xml → 测试全绿后 deploy |
| 远端 | ✅ | origin = `git@github.com:wop-platform/wop-java-sdk.git` |
| 测试/覆盖率 | ✅ | 208 tests 全绿；JaCoCo 聚合行 100.00% / 分支 100.00%（三模块门禁各 ≥98%） |
| 唯一阻断项 | ⏳ | Central Portal namespace `com.wanlianyida` 待 DNS TXT 验证（见 §1.1） |

## 1. 阶段一：一次性凭据准备（约 20 分钟，人工操作）

### 1.1 Central 账号与 namespace 验证（DNS TXT）

1. 访问 [central.sonatype.com](https://central.sonatype.com) 注册（支持 GitHub 登录）。
2. 控制台 → **Namespaces** → Add Namespace → 输入 `com.wanlianyida`。
3. Portal 生成一条 TXT 验证记录（形如 `central-verify=<随机串>`）。
4. 到 **wanlianyida.com** 的 DNS 控制台添加该 TXT 记录。
5. 回 Portal 点 **Verify**；DNS 生效通常几分钟，最长数小时。
   - ⚠️ GitHub 仓库验证**不适用**于 `com.wanlianyida`（Central 的 GitHub 验证仅接受
     `io.github.<用户/组织>` 形态）——必须走 DNS TXT。

### 1.2 用户令牌

Portal → **Account → Generate User Token** → 得到 `<token-user>:<token-pass>`。
整串（含冒号）存为 GitHub Secret：**`MAVEN_CENTRAL_TOKEN`**。

### 1.3 GPG 发布密钥

```bash
gpg --gen-key                                    # 选 ECC 或 RSA ≥3072，设置口令
gpg --armor --export <key-id>                    # 公钥 → 粘贴到 Portal → Keys 页上传
gpg --armor --export-secret-keys <key-id>        # ASCII 私钥全文 → Secret GPG_PRIVATE_KEY
# 口令 → Secret GPG_PASSPHRASE
```

Secrets 配置入口：GitHub 仓库 → Settings → Secrets and variables → Actions →
New repository secret，共 3 个：`MAVEN_CENTRAL_TOKEN` / `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE`。

## 2. 阶段二：推仓与发版

```bash
# 1) 推 main（触发 ci.yml：全量测试 + 覆盖率门禁；仓库需先在 GitHub 建为空仓，不带 README）
git push -u origin main

# 2) CI 绿后打 tag（tag 必须与根 pom 版本一致，workflow 会校验）
git tag v0.1.0 && git push origin v0.1.0
```

release.yml 自动执行：版本一致性校验 → GPG 密钥导入 → `mvn verify`（门禁再跑一遍）→
`mvn -P release -DskipTests deploy` 上传（source/javadoc/GPG 签名构件）。任一步失败即中止，不留半发布状态。

### 2.1 人工核对与手动发布（首次发版策略）

上传成功后构件处于**待发布**状态（autoPublish=false）：

1. Portal → **Publishing / Releases** 打开本次部署。
2. 核对：
   - 三模块坐标 `com.wanlianyida:wop-sdk-{core,okhttp,jdkhttp}:0.1.0`
   - 每构件四件套：主 jar / sources / javadoc / `.asc` 签名
   - POM 元数据（licenses MIT、developers、scm 指向 wop-platform/wop-java-sdk）
3. 无误后点 **Publish**。

> **不可撤回提醒**：Central 发布后坐标永久公开、不可删除。发布前发现的任何问题，
> 直接在 Portal 丢弃（Discard）该部署，修完重新打 tag（删除 tag 重推即可，workflow 幂等）。

## 3. 阶段三：发版后验证

```bash
# Portal 搜索 com.wanlianyida 出现三构件；同步到 search.maven.org 需 30 分钟～2 小时
mvn dependency:get -Dartifact=com.wanlianyida:wop-sdk-core:0.1.0

# 消费验证（任意新工程）
# <dependency><groupId>com.wanlianyida</groupId><artifactId>wop-sdk-core</artifactId><version>0.1.0</version></dependency>
```

（可选）GitHub Release Notes：仓库 → Releases → Draft new release → 选 tag `v0.1.0`。

## 4. 发版后例行事项

```bash
# 工作版本滚动（四 pom 同步）
mvn versions:set -DnewVersion=0.1.1-SNAPSHOT
git commit -am "chore: bump version to 0.1.1-SNAPSHOT"
```

后续版本重复 §2（tag `v0.1.1` …），§1 的一次性工作无需再做。

## 5. 风险与边界（决策时已知悉）

1. **namespace 永久绑定域名**：`com.wanlianyida` 经 wanlianyida.com DNS 验证后，
   该域名的持续控制权 = namespace 的持续控制权。域名到期不影响已发布构件，
   但将无法在该 namespace 下发布新版本。若域名非长期资产，唯一不依赖域名的
   替代是 `io.github.wop-platform`（需全仓坐标迁移）；**0.1.0 Publish 前是最后的低成本反悔窗口**。
2. **autoPublish=false 仅首次**：链路验证稳定后可改回 `true`（pom `central-publishing` 配置），
   减少一次人工环节；保留 false 亦可，作为每版的例行核对点。
3. **坐标决策一致性**：README 依赖示例、scm/developers（org=wop-platform）与 groupId（com.wanlianyida）
   为有意组合（组织在 GitHub，发布坐标用自有域名）；后续其他五语言 SDK 发布时保持同一 namespace 策略，
   避免六仓坐标体系分裂。
4. **PIT 变异测试**：本机环境阻塞（见 `docs/mutation-report.md` §3），未纳入发版门禁；
   恢复路径 = CI 独立 job 运行 `mvn -pl wop-sdk-core org.pitest:pitest-maven:mutationCoverage`。

## 附：本地预验命令（发版链路自检，无需凭据）

```bash
mvn -P release -DskipTests -Dgpg.skip=true package   # source+javadoc 构件链（跳过签名）
mvn verify                                            # 全量测试 + 覆盖率门禁
```

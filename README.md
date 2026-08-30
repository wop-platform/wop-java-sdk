# WOP Java SDK
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-java-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-java-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

WOP 网关商户侧官方 Java 客户端：封装协议核心（签名 / 摘要 / L2 数字信封 / 验签解密），
商户无需理解 canonicalRequest、套件推导与线上字节格式即可安全对接。

- 协议真源：[crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md)（v0.3-reviewed）+ [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)（v1.0-ratified）
- 向量真源：[crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json)（本仓 fixture 为字节级副本，禁手改）
- JDK 17+，Maven 多模块（`groupId: com.wanlianyida`，版本 0.1.0）
- 运行时依赖仅 BouncyCastle（国密 SM2/SM3/SM4 唯一路径）

| 模块 | 说明 |
|------|------|
| `wop-sdk-core` | 协议核心：套件解析、canonicalRequest、`x-wop-sign` 加验签、`x-wop-content-digest`、L2 数字信封、F6 校验顺序、I7 错误模糊化；含 `Transport` 抽象 |
| `wop-sdk-okhttp` | OkHttp 适配器（okhttp 依赖 `provided`，商户自带版本） |
| `wop-sdk-jdkhttp` | `java.net.http` 适配器（零额外依赖） |

支持套件：`WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3`。

## 快速开始

```xml
<dependency>
  <groupId>com.wanlianyida</groupId>
  <artifactId>wop-sdk-core</artifactId>
  <version>0.1.0</version>
</dependency>

<!-- 可选适配器（二选一）：okhttp 依赖 scope=provided（商户自带版本） / jdkhttp 零额外依赖 -->
<dependency>
  <groupId>com.wanlianyida</groupId>
  <artifactId>wop-sdk-okhttp</artifactId>
  <version>0.1.0</version>
</dependency>
<!-- 或 -->
<dependency>
  <groupId>com.wanlianyida</groupId>
  <artifactId>wop-sdk-jdkhttp</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
WopClient client = WopClient.builder()
        .appKey("app_001")
        .suite("WOP-RSA3072-SHA256")            // 或 WOP-RSA4096-SHA256 / WOP-SM2-SM3
        .merchantPrivateKey(merchantPrivateKey)  // PEM 或 Base64 单行
        .platformPublicKey(platformPublicKey)
        .build();

// 1) 构造请求（headers + wireBody，零网络 IO）
byte[] body = "{\"orderId\":\"W1\"}".getBytes(StandardCharsets.UTF_8);
RequestDraft draft = client.buildRequest("POST", "/gateway/order/create", body, SecurityLevel.L0);

// 2) 发送（自带 HTTP 栈时直接消费 draft；否则用官方适配器）
Transport transport = new OkHttpTransport("https://gw.example.com");
TransportResponse response = transport.send(draft);

// 3) 校验响应（F6 顺序：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密）
VerifyResult result = client.verifyResponse(response, draft);
if (result.ok()) {
    System.out.println(result.plaintextAsUtf8());
} else {
    System.out.println(result.message());   // 验签/解密失败对外模糊（I7）
}
```

## 密钥准备（D12 分发契约）

| 套件 | 商户私钥 | 平台公钥 |
|------|----------|----------|
| RSA 族 | PKCS#8 DER（PEM `-----BEGIN PRIVATE KEY-----` 或 Base64 单行）；长度须与套件一致（3072/4096） | X.509 SPKI（PEM `-----BEGIN PUBLIC KEY-----` 或 Base64 单行） |
| SM2 族 | d 标量 32 字节（Base64）或 PKCS#8；曲线固定 sm2p256v1 | 未压缩点 `04‖X‖Y` 65 字节（Base64）或 SPKI |

密钥解析在 `build()` 时 fail-fast：格式非法、长度与套件不符、跨族材料均以明确异常拒绝。

## L0 / L2 示例

```java
// L0 明文（仅签名 + 摘要完整性）：无 body 时 digest 头自动缺席（D2）
RequestDraft get = client.buildRequest("GET", "/gateway/order/get", null, SecurityLevel.L0);

// L2 全文数字信封：body → AES-256-GCM/SM4-GCM 密文信封；DEK 用平台公钥
// RSA-OAEP（显式双 SHA-256 + 空 label）/ SM2（C1C3C2）包装；digest 对密文载体计算
RequestDraft pay = client.buildRequest("POST", "/gateway/pay", body, SecurityLevel.L2);
// pay.wireBody() 即 {"encrypted":"<base64url>"}，直接作为 HTTP body 发送

// 回调校验（URI 取回调 path）
VerifyResult callback = client.verifyCallback(headers, rawBody, "/merchant/callback");
```

## 向量自测（conformance）

黄金向量 fixture 位于 `vectors/crypto-vectors.json`（真源副本，禁止手改），
测试 classpath 消费同一份；本地与 CI 一致：

```bash
mvn verify
# 全量测试（含向量 conformance 套件）+ JaCoCo 行/分支 ≥98% 门禁
```

向量覆盖面（字节级断言 + 全负向量）：SHA-256/SM3 摘要与 digest 头、AES-256-GCM/SM4-GCM
固定 key/IV 密文、RSA3072/4096 确定性签名、SM2 固定 k 签名（r‖s 64B）、OAEP 解包与
MGF1-SHA-1 陷阱、SM2 C1C3C2 解密与 C1C2C3 拒收、DEK 载荷、digest 头格式规则（双空格/
大写 hex/长度/跨族）、严格无填充 base64url。

## 错误处理与模糊化（I7）

- **出向**（`buildRequest`）：配置/协议格式错误抛 `WopSdkException`（本地明确，鉴权前可判定）
- **入向**（`verifyResponse`/`verifyCallback`）：统一返回 `VerifyResult`，永不抛异常
  - 明确类（帮助集成自查）：签名头/加密指令格式、套件不支持、digest 缺失或不匹配、DEK alg 与套件族不符、密文载体格式
  - **模糊类**（防 oracle）：`签名验证失败` / `解密失败`——不区分 tag 失败、密钥不符等细节
- 防重放辅助（F9）：每次请求 CSPRNG 生成 32 位 nonce 与毫秒时间戳；时间窗校验由网关执行

## 许可证

MIT（见 [LICENSE](LICENSE)）。

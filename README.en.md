# WOP Java SDK
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-java-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-java-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

Official Java client for the WOP gateway merchant side: encapsulates the protocol
core (signing / digest / L2 digital envelope / verify & decrypt) so merchants can
integrate securely without understanding canonicalRequest, suite derivation or
wire byte formats.

- Protocol sources: [crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md) (v0.3-reviewed) + [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md) (v1.0-ratified)
- Vector source of truth: [crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json) (byte-level copy in this repo, never edit by hand)
- JDK 17+, Maven multi-module (`groupId: com.wanlianyida`, version 0.1.0)
- Single runtime dependency: BouncyCastle (the only supported path for SM2/SM3/SM4)

| Module | Description |
|--------|-------------|
| `wop-sdk-core` | Protocol core: suite parsing, canonicalRequest, `x-wop-sign` sign/verify, `x-wop-content-digest`, L2 digital envelope, F6 verification order, I7 error obfuscation; hosts the `Transport` abstraction |
| `wop-sdk-okhttp` | OkHttp adapter (okhttp dependency is `provided`; bring your own version) |
| `wop-sdk-jdkhttp` | `java.net.http` adapter (zero extra dependencies) |

Supported suites: `WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3`.

## Quick Start

```xml
<dependency>
  <groupId>com.wanlianyida</groupId>
  <artifactId>wop-sdk-core</artifactId>
  <version>0.1.0</version>
</dependency>

<!-- Optional adapter (pick one): okhttp dependency is provided (bring your own) / jdkhttp has zero extra dependencies -->
<dependency>
  <groupId>com.wanlianyida</groupId>
  <artifactId>wop-sdk-okhttp</artifactId>
  <version>0.1.0</version>
</dependency>
<!-- or -->
<dependency>
  <groupId>com.wanlianyida</groupId>
  <artifactId>wop-sdk-jdkhttp</artifactId>
  <version>0.1.0</version>
</dependency>
```

```java
WopClient client = WopClient.builder()
        .appKey("app_001")
        .suite("WOP-RSA3072-SHA256")            // or WOP-RSA4096-SHA256 / WOP-SM2-SM3
        .merchantPrivateKey(merchantPrivateKey)  // PEM or single-line Base64
        .platformPublicKey(platformPublicKey)
        .build();

// 1) Build the request (headers + wireBody, zero network IO)
byte[] body = "{\"orderId\":\"W1\"}".getBytes(StandardCharsets.UTF_8);
RequestDraft draft = client.buildRequest("POST", "/gateway/order/create", body, SecurityLevel.L0);

// 2) Send (consume the draft with your own stack, or use an official adapter)
Transport transport = new OkHttpTransport("https://gw.example.com");
TransportResponse response = transport.send(draft);

// 3) Verify the response (F6 order: signature -> digest recheck -> DEK unwrap
//    -> alg family compare -> bulk decrypt)
VerifyResult result = client.verifyResponse(response, draft);
if (result.ok()) {
    System.out.println(result.plaintextAsUtf8());
} else {
    System.out.println(result.message());   // signature/decrypt failures are vague (I7)
}
```

## Key Preparation (D12 distribution contract)

| Suite | Merchant private key | Platform public key |
|-------|----------------------|---------------------|
| RSA family | PKCS#8 DER (PEM `-----BEGIN PRIVATE KEY-----` or single-line Base64); length must match the suite (3072/4096) | X.509 SPKI (PEM `-----BEGIN PUBLIC KEY-----` or single-line Base64) |
| SM2 family | d scalar, 32 bytes (Base64) or PKCS#8; curve fixed to sm2p256v1 | Uncompressed point `04‖X‖Y`, 65 bytes (Base64) or SPKI |

Key parsing fails fast at `build()`: illegal formats, length mismatch with the suite,
and cross-family material are all rejected with explicit exceptions.

## L0 / L2 Examples

```java
// L0 plaintext (signature + digest integrity only): the digest header is
// automatically absent when there is no body (D2)
RequestDraft get = client.buildRequest("GET", "/gateway/order/get", null, SecurityLevel.L0);

// L2 full-envelope: body -> AES-256-GCM/SM4-GCM ciphertext envelope; DEK wrapped
// with the platform public key via RSA-OAEP (explicit dual SHA-256 + empty label)
// or SM2 (C1C3C2); the digest is computed over the ciphertext carrier
RequestDraft pay = client.buildRequest("POST", "/gateway/pay", body, SecurityLevel.L2);
// pay.wireBody() is {"encrypted":"<base64url>"} - send it as the HTTP body

// Callback verification (URI = callback path)
VerifyResult callback = client.verifyCallback(headers, rawBody, "/merchant/callback");
```

## Vector Self-Test (conformance)

The golden vector fixture lives at `vectors/crypto-vectors.json` (copy of the
source of truth, never edit by hand); tests consume the same copy on the
classpath, locally and in CI:

```bash
mvn verify
# Full test run (including the vector conformance suite) + JaCoCo line/branch >= 98% gate
```

Vector coverage (byte-level assertions + all negative vectors): SHA-256/SM3 digests
and digest headers, AES-256-GCM/SM4-GCM with fixed key/IV, deterministic
RSA3072/4096 signatures, SM2 fixed-k signature (raw r‖s 64B), OAEP unwrap with the
MGF1-SHA-1 trap, SM2 C1C3C2 decryption with C1C2C3 rejection, DEK payloads, digest
header format rules (double space / uppercase hex / length / cross-family), and
strict unpadded base64url.

## Error Handling & Obfuscation (I7)

- **Outbound** (`buildRequest`): configuration/protocol format errors throw
  `WopSdkException` (explicit, locally decidable before authentication)
- **Inbound** (`verifyResponse`/`verifyCallback`): always returns a `VerifyResult`,
  never throws
  - Explicit categories (integration self-help): sign/encrypt header format,
    unsupported suite, missing or mismatched digest, DEK alg vs suite family
    mismatch, ciphertext envelope format
  - **Vague categories** (oracle hardening): `signature verification failed` /
    `decryption failed` - no detail about tag mismatch, wrong key, etc.
- Anti-replay helpers (F9): each request gets a CSPRNG 32-char nonce and a
  millisecond timestamp; the validity window is enforced by the gateway

## License

MIT (see [LICENSE](LICENSE)).

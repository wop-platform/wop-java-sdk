# language: zh-CN
功能: WOP 商户 SDK 使用场景（规格 v1.0 功能面 F1-F9 + 概念 API + 网关对接行为）

  背景:
    假如 商户持有 WOP-RSA3072-SHA256 套件的商户私钥与平台公钥
    而且 应用 appKey 为 app_001
    而且 签名字段到期窗口为 1800 秒

  # ============ F2/F4/D2/I1：出向请求构建 ============

  场景: L0 无 body 请求不产生 digest 头（D2 缺席合法）
    当 构建 L0 请求 GET /gateway/waybill-query 无 body
    那么 请求无 x-wop-content-digest 头
    而且 请求包含 appkey、timestamp、nonce、sign 头
    而且 签名头包含 appkey、timestamp、nonce

  场景: L0 有 body 请求产生 digest 且入签（I1）
    当 构建 L0 请求 POST /gateway/waybill-sync body 为 业务报文
    那么 请求含 x-wop-content-digest 头且为 "sha-256 <64位小写hex>"
    而且 签名头包含 x-wop-content-digest
    而且 wireBody 与业务报文一致

  场景: L2 请求构建数字信封（F5）
    当 构建 L2 请求 POST /gateway/waybill-sync body 为 业务报文
    那么 请求含 x-wop-encrypt 头且以 "L2;dek=" 开头
    而且 wireBody 为 密文信封
    而且 签名头包含 x-wop-encrypt 与 x-wop-content-digest
    而且 digest 是对密文 wireBody 的摘要（非明文）

  场景: 方法大小写不敏感且路径校验
    当 构建 L0 请求 "post" /gateway/waybill-query body 为 业务报文
    那么 请求方法规范化为 POST

  场景: 非法入参拒绝（F1 配置类错误）
    当 构建 L0 请求 空方法
    那么 抛出配置类异常
    当 构建 L0 请求 空路径
    那么 抛出配置类异常
    当 构建 L2 请求 无 body
    那么 抛出配置类异常（L2 需要非空 body）

  # ============ F3/F6/I7：入向响应与回调校验 ============

  场景: L0 响应验签成功
    当 平台返回 L0 响应 响应报文
    那么 校验结果 ok 为 true 且明文与原始业务响应一致

  场景: L2 响应验签解密还原明文（F6 固定顺序）
    当 平台返回 L2 响应 响应报文
    那么 校验结果 ok 为 true 且明文与原始业务响应一致

  场景: 响应签名被篡改 → 模糊拒绝（I7）
    当 平台返回 L0 响应 响应报文 但签名被篡改
    那么 校验结果 ok 为 false 且错误为签名失败模糊文案（不泄露细节）

  场景: 回调校验按 URI 取回调 path（§2）
    当 平台回调 POST /callback/waybill-status 带 L2 报文
    那么 校验结果 ok 为 true 且明文与回调业务报文一致

  场景: 响应缺 digest 头拒绝（I1 入签强制）
    当 平台返回 L0 响应 响应报文 但 digest 头缺席
    那么 校验结果 ok 为 false 且错误为缺失摘要头

  场景: 无 body 但带 digest 头拒绝（D2）
    当 平台返回无 body 的 L0 响应 但带 digest 头
    那么 校验结果 ok 为 false 且错误为摘要头非法

  场景: digest 与 body 不匹配拒绝（F6 顺序：验签先于摘要复核）
    当 平台返回 L0 响应 响应报文 但 digest 值错误
    那么 校验结果 ok 为 false 且错误为签名失败（F6 先验签）

  # ============ F1/F7/F8：套件与字节格式 ============

  场景: 非法套件字符串拒绝（F1）
    当 解析套件 "WOP-RSA1024-SHA256"
    那么 抛出套件解析异常
    当 解析套件 "WOP-RSA3072-SM3"（跨族）
    那么 抛出套件不支持异常

  场景: SM2 套件受支持且走 SM4-GCM + C1C3C2（Java 矩阵）
    当 使用 SM2-SM3 套件构建 L2 请求 body 为 业务报文
    那么 请求成功且 encrypt 头格式合法

  场景: base64url 严格模式拒绝填充（F7）
    当 解码 base64url 字符串 "abc="（带填充）
    那么 抛出非法输入异常
    当 解码 base64url 字符串 "abc+"（标准 base64 字符）
    那么 抛出非法输入异常

  # ============ D12/F9：密钥与防重放 ============

  场景: 密钥入参 PEM 与 Base64 单行等价（D12）
    当 分别用 PEM 与 Base64 单行格式构建两个客户端
    那么 两者构建同一请求的签名头一致

  场景: 非法密钥拒绝（D12 配置类错误）
    当 构建客户端 私钥为 "not-a-key"
    那么 抛出配置类异常

  场景: 防重放字段（F9）
    当 构建 L0 请求 POST /gateway/waybill-sync body 为 业务报文
    那么 nonce 为 32 位小写 hex 且每次不同
    而且 timestamp 为毫秒级时间戳

  场景: 幂等重放（§2 确定性）
    当 用固定 nonce 与固定 timestamp 构建两次相同 L0 请求
    那么 两次请求的 sign 头字节一致

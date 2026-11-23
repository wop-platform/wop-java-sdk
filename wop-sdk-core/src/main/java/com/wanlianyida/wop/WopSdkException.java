package com.wanlianyida.wop;

/**
 * SDK 显式异常：配置错误、协议头格式错误等<b>鉴权前可判定</b>的公开协议知识（10.2 明确/模糊分界原则）。
 * <p>
 * 验签/解密失败不抛本类——走 {@code VerifyResult} 模糊 reason（I7）。
 */
public class WopSdkException extends RuntimeException {

    /**
     * 传输失败发生在发送前的哪个位置。
     * <p>
     * 仅用于判定 failover 可重试性：连接超时与读超时在 JDK/OkHttp 下同为
     * {@link java.net.SocketTimeoutException}，按异常类型无法区分，必须由适配器按阶段打标。
     */
    public enum Phase {

        /** 未打标（第三方 Transport 或非传输类错误）：退回按异常类型判定。 */
        UNKNOWN,

        /** 连接尚未建立，请求字节未发出——重试无重复副作用。 */
        CONNECT,

        /** 请求字节已发出（含读响应阶段）——重试可能产生重复副作用，禁止 failover。 */
        SENT
    }

    private final Phase phase;

    /** 以明确语义消息构造（阶段 {@link Phase#UNKNOWN}）。 */
    public WopSdkException(String message) {
        this(message, null, Phase.UNKNOWN);
    }

    /** 携带底层原因构造（阶段 {@link Phase#UNKNOWN}）。 */
    public WopSdkException(String message, Throwable cause) {
        this(message, cause, Phase.UNKNOWN);
    }

    /** 携带底层原因与传输阶段构造；{@code phase} 为 null 时归一为 {@link Phase#UNKNOWN}。 */
    public WopSdkException(String message, Throwable cause, Phase phase) {
        super(message, cause);
        this.phase = phase == null ? Phase.UNKNOWN : phase;
    }

    /** 传输阶段；非传输类错误恒为 {@link Phase#UNKNOWN}。 */
    public Phase phase() {
        return phase;
    }
}

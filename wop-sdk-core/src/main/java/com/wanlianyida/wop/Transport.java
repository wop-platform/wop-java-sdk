package com.wanlianyida.wop;

/**
 * Transport 抽象（协议核心与 HTTP 栈之间的唯一边界，适配器保持薄）：
 * 消费 {@link RequestDraft}，返回 {@link TransportResponse}。
 * 传输失败（连接/超时等）抛 {@link WopSdkException}（系统类，明确）。
 */
public interface Transport {

    /** 发送草稿并返回响应快照；传输失败（连接/超时等系统类）抛 {@link WopSdkException}。 */
    TransportResponse send(RequestDraft draft);

    /**
     * 带 {@link TransportCall} 的发送（§7.1）；商户自定义 Transport 仅实现单参时走 default 回退。
     */
    default TransportResponse send(RequestDraft draft, TransportCall call) {
        return send(draft);
    }

    /** 是否显式支持 {@link #send(RequestDraft, TransportCall)}（官方适配器为 true）。 */
    default boolean supportsTransportCall() {
        return false;
    }
}

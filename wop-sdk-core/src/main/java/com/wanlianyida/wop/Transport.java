package com.wanlianyida.wop;

/**
 * Transport 抽象（协议核心与 HTTP 栈之间的唯一边界，适配器保持薄）：
 * 消费 {@link RequestDraft}，返回 {@link TransportResponse}。
 * 传输失败（连接/超时等）抛 {@link WopSdkException}（系统类，明确）。
 */
public interface Transport {

    TransportResponse send(RequestDraft draft);
}

package com.wanlianyida.wop;

import com.wanlianyida.wop.config.WopRequestContext;

import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.util.List;

/**
 * Failover 包装传输（§7.3 P2）：主网关固定优先 + 备用有序切换；仅连接阶段失败可重试（K4）。
 */
public final class FailoverTransport implements Transport {

    private final Transport delegate;
    private final List<String> candidates;
    private final int maxRetryCount;

    public FailoverTransport(Transport delegate, WopRequestContext context) {
        this.delegate = delegate;
        this.candidates = context.failoverCandidates();
        this.maxRetryCount = context.maxRetryCount();
    }

    @Override
    public TransportResponse send(RequestDraft draft) {
        return send(draft, TransportCall.empty());
    }

    @Override
    public TransportResponse send(RequestDraft draft, TransportCall call) {
        int maxAttempts = 1 + Math.min(maxRetryCount, Math.max(0, candidates.size() - 1));
        WopSdkException last = null;
        int attempted = 0;
        for (int i = 0; i < candidates.size() && attempted < maxAttempts; i++) {
            String root = candidates.get(i);
            TransportCall attemptCall = mergeCall(call, root);
            attempted++;
            try {
                return sendWithDelegate(draft, attemptCall);
            } catch (WopSdkException e) {
                if (!isPreSendRetryable(e)) {
                    throw e;
                }
                last = e;
            }
        }
        throw wrapExhausted(last, attempted);
    }

    private TransportResponse sendWithDelegate(RequestDraft draft, TransportCall attemptCall) {
        if (!delegate.supportsTransportCall()) {
            throw WopError.configuration(
                    "底层 Transport 未实现 send(RequestDraft, TransportCall)，"
                            + "无法应用 Failover 或请求级网关/超时覆盖");
        }
        return delegate.send(draft, attemptCall);
    }

    private static TransportCall mergeCall(TransportCall call, String serverRoot) {
        if (call == null) {
            return TransportCall.of(serverRoot, TransportCall.USE_DEFAULT, TransportCall.USE_DEFAULT);
        }
        return TransportCall.of(serverRoot, call.connectTimeoutMillis(), call.readTimeoutMillis());
    }

    /** 连接阶段失败可重试；读超时/已收到响应/协议错误不重试（K4）。 */
    static boolean isPreSendRetryable(WopSdkException e) {
        Throwable cause = e.getCause();
        while (cause != null) {
            if (cause instanceof ConnectException
                    || cause instanceof UnknownHostException
                    || cause instanceof NoRouteToHostException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private WopSdkException wrapExhausted(WopSdkException last, int attempted) {
        int maxAttempts = 1 + Math.min(maxRetryCount, Math.max(0, candidates.size() - 1));
        String message;
        if (attempted < candidates.size()) {
            message = "网关地址不可用（已尝试 " + attempted + " 个，已达重试上限 " + maxRetryCount + "）";
        } else {
            message = "全部网关地址不可用（已尝试 " + attempted + " 个）";
        }
        return new WopSdkException(message, last);
    }
}

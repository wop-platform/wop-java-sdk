package com.wanlianyida.wop;

public interface Transport {

    TransportResponse send(RequestDraft draft);

    default TransportResponse send(RequestDraft draft, TransportCall call) {
        return send(draft);
    }

    /** 是否显式支持 {@link #send(RequestDraft, TransportCall)}（官方适配器为 true）。 */
    default boolean supportsTransportCall() {
        return false;
    }
}

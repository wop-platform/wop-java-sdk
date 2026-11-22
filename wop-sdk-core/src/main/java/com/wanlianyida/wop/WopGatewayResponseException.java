package com.wanlianyida.wop;

public final class WopGatewayResponseException extends WopSdkException {

    private final int statusCode;
    private final byte[] body;

    public WopGatewayResponseException(int statusCode, byte[] body) {
        super(formatMessage(statusCode, body));
        this.statusCode = statusCode;
        this.body = body == null ? new byte[0] : body.clone();
    }

    public int statusCode() {
        return statusCode;
    }

    public byte[] body() {
        return body.clone();
    }

    private static String formatMessage(int statusCode, byte[] body) {
        int length = body == null ? 0 : body.length;
        return "WOP 网关返回 HTTP " + statusCode + "（响应体 " + length + " 字节）";
    }
}

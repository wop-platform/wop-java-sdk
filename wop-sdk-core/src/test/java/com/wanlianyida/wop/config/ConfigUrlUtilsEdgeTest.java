package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** ConfigUrlUtils 校验消息、URL 归一化与路径拼接。 */
class ConfigUrlUtilsEdgeTest {

    private static WopError urlError(String value, String fieldName) {
        return assertThrows(WopError.class,
                () -> ConfigUrlUtils.validateGatewayUrl(value, fieldName));
    }

    private static WopError pathError(String path) {
        return assertThrows(WopError.class, () -> ConfigUrlUtils.validateApiPath(path));
    }

    @Test
    void gatewayUrlValidationMessages() {
        assertTrue(urlError(null, "serverRoot").getMessage().contains("serverRoot 不是合法 URL: null"));
        assertTrue(urlError("   ", "serverRoot").getMessage().contains("serverRoot 不是合法 URL"));
        assertTrue(urlError("not a url", "serverRoot").getMessage().contains("serverRoot 不是合法 URL"));
        assertTrue(urlError("https://", "serverRoot").getMessage().contains("serverRoot 不是合法 URL"));
        assertTrue(urlError("http://gw.example.com/gateway", "serverRoot").getMessage()
                .contains("serverRoot 须为 HTTPS 绝对 URL"));
        assertTrue(urlError("/gateway", "serverRoot").getMessage()
                .contains("serverRoot 须为 HTTPS 绝对 URL"));
        assertTrue(urlError("https://gw.example.com/gateway?q=1", "backupServerRoots[0]").getMessage()
                .contains("backupServerRoots[0] 不得含 query 或 fragment"));
        assertTrue(urlError("https://gw.example.com/gateway#f", "serverRoot").getMessage()
                .contains("serverRoot 不得含 query 或 fragment"));
        assertTrue(urlError("https://user:pw@gw.example.com/gateway", "serverRoot").getMessage()
                .contains("serverRoot 不得含 user-info"));
        // 空 authority（host 为 null）→ 不是合法 URL
        assertTrue(urlError("https:///x", "serverRoot").getMessage().contains("serverRoot 不是合法 URL"));
    }

    @Test
    void gatewayUrlNormalization() {
        assertEquals("https://gw.example.com/gateway",
                ConfigUrlUtils.validateGatewayUrl("HTTPS://GW.Example.COM/gateway", "serverRoot"));
        assertEquals("https://gw.example.com:8443/gateway",
                ConfigUrlUtils.validateGatewayUrl("https://gw.example.com:8443/gateway", "serverRoot"));
        assertEquals("https://gw.example.com",
                ConfigUrlUtils.validateGatewayUrl("https://gw.example.com", "serverRoot"));
        assertEquals("https://gw.example.com",
                ConfigUrlUtils.validateGatewayUrl("https://gw.example.com/", "serverRoot"));
        // 空 user-info（"@" 存在但无凭证）→ 不视为携带凭证，正常归一化
        assertEquals("https://gw.example.com/gateway",
                ConfigUrlUtils.validateGatewayUrl("https://@gw.example.com/gateway", "serverRoot"));
    }

    @Test
    void apiPathValidationMessages() {
        assertTrue(pathError(null).getMessage().contains("请求路径为空"));
        assertTrue(pathError("   ").getMessage().contains("请求路径为空"));
        assertTrue(pathError("gateway/x").getMessage().contains("path 须以 / 开头: gateway/x"));
        assertTrue(pathError("//gateway/x").getMessage().contains("path 不得 // 开头: //gateway/x"));
        assertTrue(pathError("/gateway/x?q=1").getMessage().contains("不得含 query 或 fragment"));
        assertTrue(pathError("/gateway/x#f").getMessage().contains("不得含 query 或 fragment"));
    }

    @Test
    void joinUrlComposesRootAndPath() {
        assertEquals("https://gw.example.com/gateway/p",
                ConfigUrlUtils.joinUrl("https://gw.example.com/gateway", "/p"));
        assertEquals("https://gw.example.com/gateway/p",
                ConfigUrlUtils.joinUrl("https://gw.example.com/gateway/", "/p"));
    }
}

package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PIT r2 补测：配置装载链的边界与 hashCode（ConditionalsBoundary / VoidMethodCall / PrimitiveReturns 变异）。
 */
class MutationKillConfigTest {

    @TempDir
    Path tempDir;

    private String savedUserDir;
    private String savedUserHome;
    private String savedConfigFileProperty;
    private ClassLoader savedTccl;

    @BeforeEach
    void setUp() {
        savedUserDir = System.getProperty("user.dir");
        savedUserHome = System.getProperty("user.home");
        savedConfigFileProperty = System.getProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        savedTccl = Thread.currentThread().getContextClassLoader();
        WopSdkConfigLoader.clearCache();
    }

    @AfterEach
    void tearDown() {
        System.setProperty("user.dir", savedUserDir);
        System.setProperty("user.home", savedUserHome);
        if (savedConfigFileProperty == null) {
            System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        } else {
            System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, savedConfigFileProperty);
        }
        Thread.currentThread().setContextClassLoader(savedTccl);
        WopSdkConfigLoader.clearCache();
    }

    @Test
    void loadDefaultMissMessageSeparatesCandidatesWithoutLeadingSemicolon() throws Exception {
        Path emptyDir = Files.createDirectories(tempDir.resolve("empty"));
        System.setProperty("user.dir", emptyDir.toString());
        System.setProperty("user.home", emptyDir.toString());
        System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        // 屏蔽 classpath 候选：空父加载器读不到任何资源
        Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
        });
        WopSdkConfigLoader.clearCache();

        String message = assertThrows(WopError.class, WopSdkConfigLoader::loadDefault).getMessage();
        assertTrue(message.startsWith("未找到可读的配置文件，已尝试："), message);
        // 分隔符只应出现在候选项之间，若循环从 i=0 开始拼接则出现 "已尝试：; "
        assertFalse(message.contains("已尝试：; "), message);
    }

    @Test
    void joinUrlRejectsPathWithoutLeadingSlash() {
        WopError error = assertThrows(WopError.class,
                () -> ConfigUrlUtils.joinUrl("https://gw.example.com/gateway", "no-slash"));
        assertTrue(error.getMessage().contains("path 须以 / 开头"), error.getMessage());
    }

    @Test
    void httpClientSettingsHashDependsOnFields() {
        assertNotEquals(new HttpClientSettings(1000, 2000, 0).hashCode(),
                new HttpClientSettings(1000, 2001, 0).hashCode());
    }

    @Test
    void sdkConfigHashDependsOnFields() {
        WopSdkConfig a = new WopSdkConfig("app_001", "WOP-RSA3072-SHA256", "priv-a", "pub-a",
                "https://gw.example.com/gateway", Collections.emptyList(), 1800L, new HttpClientSettings(1000, 2000, 0), null);
        WopSdkConfig b = new WopSdkConfig("app_002", "WOP-RSA3072-SHA256", "priv-b", "pub-b",
                "https://gw.example.com/gateway", Collections.emptyList(), 1801L, new HttpClientSettings(1000, 2001, 0), null);
        assertNotEquals(a.hashCode(), b.hashCode());
    }
}

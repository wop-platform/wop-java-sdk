package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopClient;
import com.wanlianyida.wop.WopError;
import com.wanlianyida.wop.crypto.TestVectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * WopSdkConfigLoader 装载矩阵（§4）：显式路径校验、classpath 读取失败与多轮读缓冲、
 * 发现链候选与全 miss 消息、显式不可读 fail-fast、按位置缓存。
 */
class WopSdkConfigLoaderEdgeTest {

    private static final String RSA_PRIV = TestVectors.keys("rsa3072").path("privatePkcs8B64").asText();
    private static final String RSA_PUB = TestVectors.keys("rsa3072").path("publicSpkiB64").asText();

    private String savedUserDir;
    private String savedUserHome;
    private String savedConfigFileProperty;
    private ClassLoader savedTccl;

    @BeforeEach
    void saveEnvironment() {
        savedUserDir = System.getProperty("user.dir");
        savedUserHome = System.getProperty("user.home");
        savedConfigFileProperty = System.getProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        savedTccl = Thread.currentThread().getContextClassLoader();
    }

    @AfterEach
    void restoreEnvironment() {
        if (savedUserDir == null) {
            System.clearProperty("user.dir");
        } else {
            System.setProperty("user.dir", savedUserDir);
        }
        if (savedUserHome == null) {
            System.clearProperty("user.home");
        } else {
            System.setProperty("user.home", savedUserHome);
        }
        if (savedConfigFileProperty == null) {
            System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        } else {
            System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, savedConfigFileProperty);
        }
        Thread.currentThread().setContextClassLoader(savedTccl);
        WopSdkConfigLoader.clearCache();
        WopClient.resetDefault();
    }

    private static String baseJson() {
        return "{\"appKey\":\"app_001\",\"suite\":\"WOP-RSA3072-SHA256\""
                + ",\"merchantPrivateKey\":\"" + RSA_PRIV + "\""
                + ",\"platformPublicKey\":\"" + RSA_PUB + "\""
                + ",\"serverRoot\":\"https://gw.example.com/gateway\"}";
    }

    @Test
    void loadRejectsBlankLocation() {
        assertTrue(assertThrows(WopError.class, () -> WopSdkConfigLoader.load((String) null))
                .getMessage().contains("配置文件路径不能为空"));
        assertTrue(assertThrows(WopError.class, () -> WopSdkConfigLoader.load("   "))
                .getMessage().contains("配置文件路径不能为空"));
    }

    @Test
    void loadRejectsBlankClasspathResource() {
        assertTrue(assertThrows(WopError.class, () -> WopSdkConfigLoader.load("classpath:"))
                .getMessage().contains("classpath 资源路径为空"));
        assertTrue(assertThrows(WopError.class, () -> WopSdkConfigLoader.load("classpath:   "))
                .getMessage().contains("classpath 资源路径为空"));
    }

    @Test
    void loadRejectsMissingClasspathResource() {
        assertTrue(assertThrows(WopError.class,
                        () -> WopSdkConfigLoader.load("classpath:definitely-missing-7f3a.json"))
                .getMessage().contains("classpath 配置文件不可读"));
    }

    @Test
    void loadRejectsNullPath() {
        assertThrows(NullPointerException.class, () -> WopSdkConfigLoader.load((java.nio.file.Path) null));
    }

    @Test
    void loadRejectsMissingFile(@TempDir Path tempDir) {
        WopError e = assertThrows(WopError.class,
                () -> WopSdkConfigLoader.load(tempDir.resolve("missing.json")));
        assertTrue(e.getMessage().contains("配置文件不可读"), e.getMessage());
        assertTrue(e.getMessage().contains("missing.json"));
    }

    @Test
    void loadRejectsUnreadableFile(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("no-read-perm.json");
        Files.write(file, baseJson().getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("-w-------"));
        try {
            WopError e = assertThrows(WopError.class, () -> WopSdkConfigLoader.load(file));
            assertTrue(e.getMessage().contains("配置文件不可读"), e.getMessage());
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void classpathReadFailureSurfaces() {
        Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                return new InputStream() {
                    @Override
                    public int read() throws IOException {
                        throw new IOException("boom");
                    }

                    @Override
                    public int read(byte[] b, int off, int len) throws IOException {
                        throw new IOException("boom");
                    }
                };
            }
        });
        WopError e = assertThrows(WopError.class, () -> WopSdkConfigLoader.load("classpath:boom.json"));
        assertTrue(e.getMessage().contains("配置文件读取失败"), e.getMessage());
        assertTrue(e.getMessage().contains("classpath:boom.json"));
    }

    @Test
    void largeClasspathConfigSpansReadBuffer() {
        StringBuilder pad = new StringBuilder();
        for (int i = 0; i < 9000; i++) {
            pad.append('x');
        }
        String json = baseJson();
        final byte[] data = (json.substring(0, json.length() - 1)
                + ",\"pad\":\"" + pad + "\"}").getBytes(StandardCharsets.UTF_8);
        Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                return new ByteArrayInputStream(data);
            }
        });
        WopSdkConfig cfg = WopSdkConfigLoader.load("classpath:big.json");
        assertEquals("app_001", cfg.appKey());
    }

    @Test
    void loadDefaultMissesEveryCandidate(@TempDir Path tempDir) throws IOException {
        Path cwd = Files.createDirectories(tempDir.resolve("cwd"));
        Path home = Files.createDirectories(tempDir.resolve("home"));
        System.setProperty("user.dir", cwd.toAbsolutePath().toString());
        System.setProperty("user.home", home.toAbsolutePath().toString());
        System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
        });
        WopError e = assertThrows(WopError.class, WopSdkConfigLoader::loadDefault);
        assertTrue(e.getMessage().contains("未找到可读的配置文件，已尝试："), e.getMessage());
        assertTrue(e.getMessage().contains("{cwd}/config/wopSdkConfig.json"), e.getMessage());
        assertTrue(e.getMessage().contains("{cwd}/wopSdkConfig.json"), e.getMessage());
        assertTrue(e.getMessage().contains("{userHome}/.wop/wopSdkConfig.json"), e.getMessage());
        assertTrue(e.getMessage().contains("config/wopSdkConfig.json"));
    }

    @Test
    void loadDefaultHitsWorkingDirectoryConfig(@TempDir Path tempDir) throws IOException {
        Path cwd = Files.createDirectories(tempDir.resolve("cwd"));
        Files.createDirectories(tempDir.resolve("home"));
        Files.write(Files.createDirectories(cwd.resolve("config")).resolve("wopSdkConfig.json"),
                baseJson().getBytes(StandardCharsets.UTF_8));
        System.setProperty("user.dir", cwd.toAbsolutePath().toString());
        System.setProperty("user.home", tempDir.resolve("home").toAbsolutePath().toString());
        System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        Thread.currentThread().setContextClassLoader(new ClassLoader(null) {
        });
        assertEquals("app_001", WopSdkConfigLoader.loadDefault().appKey());
    }

    @Test
    void loadDefaultFailsFastOnUnreadableExplicitPath(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("secret.json");
        Files.write(file, baseJson().getBytes(StandardCharsets.UTF_8));
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("-w-------"));
        System.setProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY, file.toAbsolutePath().toString());
        try {
            WopError e = assertThrows(WopError.class, WopSdkConfigLoader::loadDefault);
            assertTrue(e.getMessage().contains("显式配置文件不可读"), e.getMessage());
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void defaultDiscoveryCandidatesMatrix() {
        assertEquals(4, WopSdkConfigLoader.defaultDiscoveryCandidates(null, null).size());
        assertEquals(1, WopSdkConfigLoader.defaultDiscoveryCandidates("x.json", "y.json").size());
        assertEquals(1, WopSdkConfigLoader.defaultDiscoveryCandidates("   ", "y.json").size());
        assertEquals(4, WopSdkConfigLoader.defaultDiscoveryCandidates(null, "   ").size());
        assertEquals(1, WopSdkConfigLoader.defaultDiscoveryCandidates("x.json", null).size());
    }

    @Test
    void loadAbsolutePathFromString(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("abs.json");
        Files.write(file, baseJson().getBytes(StandardCharsets.UTF_8));
        assertEquals("app_001", WopSdkConfigLoader.load(file.toAbsolutePath().toString()).appKey());
    }

    @Test
    void cachedLoadReusesInstanceUntilCleared(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("cached.json");
        Files.write(file, baseJson().getBytes(StandardCharsets.UTF_8));
        WopSdkConfig first = WopSdkConfigLoader.load(file);
        assertSame(first, WopSdkConfigLoader.load(file));
        WopSdkConfigLoader.clearCache();
        assertNotSame(first, WopSdkConfigLoader.load(file));
    }

    @Test
    void loadDefaultFallsBackToOwnClassLoaderWhenTcclNull(@TempDir Path tempDir) throws IOException {
        // 文件候选全空 + TCCL 为 null → classpath 候选经 WopSdkConfigLoader 自身类加载器发现并读取
        // （test-resources 预置 config/wopSdkConfig.json）
        Path cwd = Files.createDirectories(tempDir.resolve("cwd"));
        Path home = Files.createDirectories(tempDir.resolve("home"));
        System.setProperty("user.dir", cwd.toAbsolutePath().toString());
        System.setProperty("user.home", home.toAbsolutePath().toString());
        System.clearProperty(WopSdkConfigLoader.CONFIG_FILE_PROPERTY);
        Thread.currentThread().setContextClassLoader(null);
        assertEquals("app_001", WopSdkConfigLoader.loadDefault().appKey());
    }
}

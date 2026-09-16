package com.wanlianyida.wop.config;

import com.wanlianyida.wop.WopError;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * 配置加载入口（§4）：线程安全缓存；Java 优先级 1 为 JVM 系统属性 {@link #CONFIG_FILE_PROPERTY}。
 */
public final class WopSdkConfigLoader {

    /** JVM 系统属性：显式配置文件路径（§4.2 优先级 1，附录 A.3）。 */
    public static final String CONFIG_FILE_PROPERTY = "wop.sdk.config.file";

    /** 环境变量：配置文件路径（§4.2 优先级 2）。 */
    public static final String CONFIG_FILE_ENV = "WOP_SDK_CONFIG";

    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String PACKAGED_CONFIG = "config/wopSdkConfig.json";
    private static final String PACKAGED_DEFAULT = "config/wopSdkConfigDefault.json";

    private static final Object CACHE_LOCK = new Object();
    private static final Map<String, WopSdkConfig> CACHE = new LinkedHashMap<>();

    private WopSdkConfigLoader() {
    }

    /** 按 §4.2 自动发现并加载；同一位置缓存解析结果。 */
    public static WopSdkConfig loadDefault() {
        List<DiscoveryCandidate> candidates = defaultDiscoveryCandidates();
        for (DiscoveryCandidate candidate : candidates) {
            if (candidate.explicit && !candidate.readable) {
                throw WopError.configuration("显式配置文件不可读: " + candidate.display);
            }
            if (!candidate.readable) {
                continue;
            }
            return loadCached(candidate.cacheKey, candidate.reader);
        }
        StringBuilder message = new StringBuilder("未找到可读的配置文件，已尝试：");
        for (int i = 0; i < candidates.size(); i++) {
            if (i > 0) {
                message.append("; ");
            }
            message.append(candidates.get(i).display);
        }
        throw WopError.configuration(message.toString());
    }

    /**
     * 显式位置加载；{@code classpath:} 前缀走 classpath，其余为文件系统路径（K14）。
     */
    public static WopSdkConfig load(String location) {
        if (location == null || location.trim().isEmpty()) {
            throw WopError.configuration("配置文件路径不能为空");
        }
        String trimmed = location.trim();
        if (trimmed.startsWith(CLASSPATH_PREFIX)) {
            String resource = trimmed.substring(CLASSPATH_PREFIX.length()).trim();
            if (resource.isEmpty()) {
                throw WopError.configuration("classpath 资源路径为空");
            }
            String cacheKey = "classpath:" + resource;
            return loadCached(cacheKey, () -> readClasspathUtf8(resource, trimmed));
        }
        return load(Paths.get(trimmed));
    }

    /** 显式文件系统路径加载。 */
    public static WopSdkConfig load(Path path) {
        Objects.requireNonNull(path, "path");
        Path normalized = path.toAbsolutePath().normalize();
        String cacheKey = "file:" + normalized;
        return loadCached(cacheKey, () -> readFileUtf8(normalized, true));
    }

    /** 清除加载缓存（测试 / 配置轮换编排，K13/K26）。 */
    public static void clearCache() {
        synchronized (CACHE_LOCK) {
            CACHE.clear();
        }
    }

    private static WopSdkConfig loadCached(String cacheKey, ConfigReader reader) {
        synchronized (CACHE_LOCK) {
            WopSdkConfig cached = CACHE.get(cacheKey);
            if (cached != null) {
                return cached;
            }
        }
        WopSdkConfig parsed = ConfigJsonParser.parse(reader.readUtf8());
        synchronized (CACHE_LOCK) {
            WopSdkConfig cached = CACHE.get(cacheKey);
            if (cached != null) {
                return cached;
            }
            CACHE.put(cacheKey, parsed);
            return parsed;
        }
    }

    private static List<DiscoveryCandidate> defaultDiscoveryCandidates() {
        List<DiscoveryCandidate> out = new ArrayList<>();

        String sysProp = System.getProperty(CONFIG_FILE_PROPERTY);
        if (sysProp != null && !sysProp.trim().isEmpty()) {
            Path path = Paths.get(sysProp.trim());
            out.add(fileCandidate(path, sysProp.trim(), true));
            return out;
        }

        String env = System.getenv(CONFIG_FILE_ENV);
        if (env != null && !env.trim().isEmpty()) {
            Path path = Paths.get(env.trim());
            out.add(fileCandidate(path, env.trim(), true));
            return out;
        }

        String cwd = System.getProperty("user.dir", ".");
        String home = System.getProperty("user.home", ".");
        out.add(fileCandidate(Paths.get(cwd, "config", "wopSdkConfig.json"),
                "{cwd}/config/wopSdkConfig.json", false));
        out.add(fileCandidate(Paths.get(cwd, "wopSdkConfig.json"),
                "{cwd}/wopSdkConfig.json", false));
        out.add(fileCandidate(Paths.get(home, ".wop", "wopSdkConfig.json"),
                "{userHome}/.wop/wopSdkConfig.json", false));
        out.add(classpathCandidate(PACKAGED_CONFIG, PACKAGED_CONFIG));
        out.add(classpathCandidate(PACKAGED_DEFAULT, PACKAGED_DEFAULT));
        return out;
    }

    private static DiscoveryCandidate fileCandidate(Path path, String display, boolean explicit) {
        Path normalized = path.toAbsolutePath().normalize();
        boolean readable = Files.isRegularFile(normalized) && Files.isReadable(normalized);
        String cacheKey = "file:" + normalized;
        return new DiscoveryCandidate(cacheKey, display, readable, explicit,
                () -> readFileUtf8(normalized, explicit));
    }

    private static DiscoveryCandidate classpathCandidate(String resource, String display) {
        boolean readable = classpathResourceExists(resource);
        String cacheKey = "classpath:" + resource;
        return new DiscoveryCandidate(cacheKey, display, readable, false,
                () -> readClasspathUtf8(resource, display));
    }

    private static boolean classpathResourceExists(String resource) {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = WopSdkConfigLoader.class.getClassLoader();
        }
        return cl.getResource(resource) != null;
    }

    private static String readFileUtf8(Path path, boolean explicit) {
        if (!Files.isRegularFile(path)) {
            if (explicit) {
                throw WopError.configuration("显式配置文件不可读: " + path);
            }
            throw WopError.configuration("配置文件不可读: " + path);
        }
        if (!Files.isReadable(path)) {
            throw WopError.configuration(
                    (explicit ? "显式配置文件不可读: " : "配置文件不可读: ") + path);
        }
        try {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw WopError.configuration("配置文件读取失败: " + path, e);
        }
    }

    private static String readClasspathUtf8(String resource, String display) {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = WopSdkConfigLoader.class.getClassLoader();
        }
        try (InputStream in = cl.getResourceAsStream(resource)) {
            if (in == null) {
                throw WopError.configuration("classpath 配置文件不可读: " + display);
            }
            byte[] bytes = readAllBytes(in);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw WopError.configuration("classpath 配置文件读取失败: " + display, e);
        }
    }

    private static byte[] readAllBytes(InputStream in) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        int total = 0;
        byte[] data = new byte[0];
        while ((read = in.read(buffer)) != -1) {
            byte[] next = new byte[total + read];
            System.arraycopy(data, 0, next, 0, total);
            System.arraycopy(buffer, 0, next, total, read);
            data = next;
            total += read;
        }
        return data;
    }

    private interface ConfigReader {
        String readUtf8();
    }

    private static final class DiscoveryCandidate {
        private final String cacheKey;
        private final String display;
        private final boolean readable;
        private final boolean explicit;
        private final ConfigReader reader;

        private DiscoveryCandidate(String cacheKey, String display, boolean readable,
                                   boolean explicit, ConfigReader reader) {
            this.cacheKey = cacheKey;
            this.display = display;
            this.readable = readable;
            this.explicit = explicit;
            this.reader = reader;
        }
    }
}

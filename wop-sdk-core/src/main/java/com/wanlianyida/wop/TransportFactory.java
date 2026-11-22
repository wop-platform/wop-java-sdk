package com.wanlianyida.wop;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

public interface TransportFactory {

    String TRANSPORT_PROPERTY = "wop.transport";

    /**
     * factory 名：稳定小写标识（P2 的 {@code wop.transport} 属性按名匹配；
     * 官方注册名为 {@code jdkhttp} / {@code okhttp} / {@code unirest}）。
     */
    String name();

    Transport create(String serverRoot);

    static TransportFactory discover() {
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        if (tccl != null) {
            try {
                return discover(tccl);
            } catch (WopError e) {
                if (!e.getMessage().startsWith("classpath 未发现 TransportFactory")) {
                    throw e;
                }
            }
        }
        return discover(TransportFactory.class.getClassLoader());
    }

    /**
     * 显式 ClassLoader 版本（测试与隔离类加载环境使用）。
     * P0 规则：恰一即用；零个 / 多个均 {@link WopError#configuration(String)} fail-fast。
     */
    static TransportFactory discover(ClassLoader classLoader) {
        List<TransportFactory> found = new ArrayList<>();
        try {
            for (TransportFactory factory : ServiceLoader.load(TransportFactory.class, classLoader)) {
                found.add(factory);
            }
        } catch (ServiceConfigurationError e) {
            throw WopError.configuration("TransportFactory SPI 注册项加载失败: " + e.getMessage(), e);
        }
        if (found.isEmpty()) {
            throw WopError.configuration("classpath 未发现 TransportFactory（查找方式：META-INF/services/"
                    + TransportFactory.class.getName()
                    + "）；请引入 wop-sdk-jdkhttp / wop-sdk-okhttp / wop-sdk-unirest 传输模块之一");
        }
        List<String> names = new ArrayList<>();
        for (TransportFactory factory : found) {
            try {
                names.add(factory.name());
            } catch (RuntimeException e) {
                throw WopError.configuration(
                        "TransportFactory SPI 注册项 name() 失败: " + factory.getClass().getName(), e);
            }
        }
        String explicit = System.getProperty(TRANSPORT_PROPERTY);
        if (explicit != null && !explicit.trim().isEmpty()) {
            String wanted = explicit.trim().toLowerCase(java.util.Locale.ROOT);
            for (TransportFactory factory : found) {
                if (wanted.equals(factory.name().toLowerCase(java.util.Locale.ROOT))) {
                    return factory;
                }
            }
            throw WopError.configuration("wop.transport=" + explicit + " 无匹配 factory；可用: "
                    + String.join(", ", names));
        }
        if (found.size() == 1) {
            return found.get(0);
        }
        for (TransportFactory factory : found) {
            if ("jdkhttp".equalsIgnoreCase(factory.name())) {
                return factory;
            }
        }
        throw WopError.configuration("classpath 存在多个 TransportFactory（" + String.join(", ", names)
                + "）；请通过 -Dwop.transport=<name> 显式指定，或仅保留一个传输模块");
    }
}

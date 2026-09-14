package com.wanlianyida.wop;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

/**
 * Transport SPI 工厂（config-spec §2.2，K18）。
 *
 * <p>依赖方向为 适配器 → core：core 无法编译依赖具体传输实现，默认传输的构造
 * 唯一无环路径是 ServiceLoader SPI——各适配器模块经
 * {@code META-INF/services/com.wanlianyida.wop.TransportFactory} 注册本接口实现。
 *
 * <p>P0 发现规则（K18）：classpath 上恰一个 factory 即用；零个或多个均以
 * {@link WopError#configuration(String)} fail-fast（多 factory 默认选择与
 * {@code wop.transport} 系统属性属 P2，未随本版落地）。
 */
public interface TransportFactory {

    /**
     * factory 名：稳定小写标识（P2 的 {@code wop.transport} 属性按名匹配；
     * 官方注册名为 {@code jdkhttp} / {@code okhttp} / {@code unirest}）。
     */
    String name();

    /**
     * 以网关根地址构造传输实例（serverRoot 须含 context-path，语义同各适配器的
     * baseUrl 构造器；域名恒由 serverRoot 供给，K14）。
     */
    Transport create(String serverRoot);

    /**
     * 发现 classpath 上的 TransportFactory（线程上下文 ClassLoader 优先，
     * 回退本类 ClassLoader，与 config-spec §4.2 的 classpath 读取约定一致）。
     */
    static TransportFactory discover() {
        ClassLoader tccl = Thread.currentThread().getContextClassLoader();
        return discover(tccl != null ? tccl : TransportFactory.class.getClassLoader());
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
        if (found.size() == 1) {
            return found.get(0);
        }
        if (found.isEmpty()) {
            throw WopError.configuration("classpath 未发现 TransportFactory（查找方式：META-INF/services/"
                    + TransportFactory.class.getName()
                    + "）；请引入 wop-sdk-jdkhttp / wop-sdk-okhttp / wop-sdk-unirest 传输模块之一");
        }
        List<String> names = new ArrayList<>();
        for (TransportFactory factory : found) {
            names.add(factory.name());
        }
        throw WopError.configuration("classpath 存在多个 TransportFactory（" + String.join(", ", names)
                + "）；多传输选择规则未落地（P2），请仅保留一个传输模块");
    }
}

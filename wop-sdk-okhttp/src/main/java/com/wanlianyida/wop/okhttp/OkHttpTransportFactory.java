package com.wanlianyida.wop.okhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;

/**
 * okhttp TransportFactory（config-spec §2.2，K18）：
 * 经 {@code META-INF/services/com.wanlianyida.wop.TransportFactory} 注册，
 * 供 core 经 ServiceLoader 无环发现；{@link #create(String)} 以 serverRoot 构造
 * {@link OkHttpTransport}（OkHttp 客户端实例与超时由商户注入路径另行提供，
 * 本工厂使用适配器默认实例）。
 */
public final class OkHttpTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "okhttp";
    }

    @Override
    public Transport create(String serverRoot) {
        return new OkHttpTransport(serverRoot);
    }
}

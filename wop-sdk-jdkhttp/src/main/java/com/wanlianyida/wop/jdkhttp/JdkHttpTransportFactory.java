package com.wanlianyida.wop.jdkhttp;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;

/**
 * jdkhttp TransportFactory（config-spec §2.2，K18）：
 * 经 {@code META-INF/services/com.wanlianyida.wop.TransportFactory} 注册，
 * 供 core 经 ServiceLoader 无环发现；{@link #create(String)} 以 serverRoot 构造
 * {@link JdkHttpTransport}（连接超时 10s 等 transport 行为由适配器自带）。
 */
public final class JdkHttpTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "jdkhttp";
    }

    @Override
    public Transport create(String serverRoot) {
        return new JdkHttpTransport(serverRoot);
    }
}

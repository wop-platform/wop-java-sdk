package com.wanlianyida.wop.unirest;

import com.wanlianyida.wop.Transport;
import com.wanlianyida.wop.TransportFactory;

/**
 * unirest TransportFactory（config-spec §2.2，K18）：
 * 经 {@code META-INF/services/com.wanlianyida.wop.TransportFactory} 注册，
 * 供 core 经 ServiceLoader 无环发现；{@link #create(String)} 以 serverRoot 构造
 * {@link UnirestTransport}（连接超时 10s、关闭 gzip 协商等实例级配置由适配器默认路径自带）。
 */
public final class UnirestTransportFactory implements TransportFactory {

    @Override
    public String name() {
        return "unirest";
    }

    @Override
    public Transport create(String serverRoot) {
        return new UnirestTransport(serverRoot);
    }
}

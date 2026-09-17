package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TransportFactory SPI 发现三态（config-spec §2.2/K18，§13.1 测试点 1）：
 * 恰一即用、零/多 fail-fast、注册项损坏包装为 {@code WopError.configuration}。
 * <p>
 * core 测试 classpath 经 META-INF/services 恰注册一个测试 factory（alpha）构造「恰一」态；
 * 「零」态用 parent=null 的隔离 URLClassLoader（仅 core 类目录，无注册文件）；
 * 「多」态与损坏态用临时 services 目录叠加测试 classpath（同名注册由 ServiceLoader 去重）。
 */
class TransportFactoryDiscoveryTest {

    @Test
    void singleFactoryIsUsedDirectly() {
        // 恰一即用（K18）：唯一注册项直接返回，无歧义
        TransportFactory factory = TransportFactory.discover(TransportFactoryDiscoveryTest.class.getClassLoader());
        assertEquals("alpha", factory.name());
        assertInstanceOf(TestAlphaTransportFactory.class, factory);
        assertInstanceOf(TestStubTransport.class, factory.create("https://gw.example.com/gtsp-wop-gateway"));
    }

    @Test
    void noArgDiscoverUsesContextClassLoader() {
        // Surefire TCCL = 测试 classpath → 同样命中唯一注册项
        assertEquals("alpha", TransportFactory.discover().name());
    }

    @Test
    void nullContextClassLoaderFallsBackToOwnLoader() {
        Thread current = Thread.currentThread();
        ClassLoader original = current.getContextClassLoader();
        current.setContextClassLoader(null);
        try {
            assertEquals("alpha", TransportFactory.discover().name());
        } finally {
            current.setContextClassLoader(original);
        }
    }

    @Test
    void emptyTcclFallsBackToDefiningLoader(@TempDir Path tempDir) throws IOException {
        // 回归（PR#35 评审）：TCCL 非空但服务目录为空（看不到 SPI 注册）→ 回退定义类加载器仍可发现
        try (URLClassLoader emptyTccl = new URLClassLoader(new URL[]{tempDir.toUri().toURL()}, null)) {
            Thread current = Thread.currentThread();
            ClassLoader original = current.getContextClassLoader();
            current.setContextClassLoader(emptyTccl);
            try {
                assertEquals("alpha", TransportFactory.discover().name());
            } finally {
                current.setContextClassLoader(original);
            }
        }
    }

    @Test
    void zeroFactoriesFailFastWithLookupHint() throws IOException {
        // 零态：隔离 loader 仅含 core 类目录，无任何 META-INF/services 注册
        URL coreClasses = TransportFactory.class.getProtectionDomain().getCodeSource().getLocation();
        try (URLClassLoader isolated = new URLClassLoader(new URL[]{coreClasses}, null)) {
            WopError ex = assertThrows(WopError.class, () -> TransportFactory.discover(isolated));
            assertEquals(WopError.Category.configuration, ex.category());
            assertTrue(ex.getMessage().contains("META-INF/services/com.wanlianyida.wop.TransportFactory"),
                    ex.getMessage());
            assertTrue(ex.getMessage().contains("wop-sdk-jdkhttp"), ex.getMessage());
        }
    }

    @Test
    void multipleFactoriesFailFastListingNames(@TempDir Path tempDir) throws IOException {
        // 多态且无 jdkhttp：须 -Dwop.transport= 显式指定
        writeServices(tempDir, "com.wanlianyida.wop.TestAlphaTransportFactory\n"
                + "com.wanlianyida.wop.TestBetaTransportFactory\n");
        try (URLClassLoader multi = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                TransportFactoryDiscoveryTest.class.getClassLoader())) {
            WopError ex = assertThrows(WopError.class, () -> TransportFactory.discover(multi));
            assertEquals(WopError.Category.configuration, ex.category());
            assertTrue(ex.getMessage().contains("alpha"), ex.getMessage());
            assertTrue(ex.getMessage().contains("beta"), ex.getMessage());
            assertTrue(ex.getMessage().contains("wop.transport"), ex.getMessage());
        }
    }

    @Test
    void multipleFactoriesPreferJdkhttpByDefault(@TempDir Path tempDir) throws IOException {
        writeServices(tempDir, "com.wanlianyida.wop.TestAlphaTransportFactory\n"
                + "com.wanlianyida.wop.TestJdkhttpTransportFactory\n");
        try (URLClassLoader multi = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                TransportFactoryDiscoveryTest.class.getClassLoader())) {
            assertEquals("jdkhttp", TransportFactory.discover(multi).name());
        }
    }

    @Test
    void wopTransportSelectsExplicitFactory(@TempDir Path tempDir) throws IOException {
        writeServices(tempDir, "com.wanlianyida.wop.TestAlphaTransportFactory\n"
                + "com.wanlianyida.wop.TestBetaTransportFactory\n");
        String previous = System.getProperty(TransportFactory.TRANSPORT_PROPERTY);
        System.setProperty(TransportFactory.TRANSPORT_PROPERTY, "beta");
        try (URLClassLoader multi = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                TransportFactoryDiscoveryTest.class.getClassLoader())) {
            assertEquals("beta", TransportFactory.discover(multi).name());
        } finally {
            if (previous == null) {
                System.clearProperty(TransportFactory.TRANSPORT_PROPERTY);
            } else {
                System.setProperty(TransportFactory.TRANSPORT_PROPERTY, previous);
            }
        }
    }

    @Test
    void wopTransportMismatchWithSingleFactoryFailsFast() {
        String previous = System.getProperty(TransportFactory.TRANSPORT_PROPERTY);
        System.setProperty(TransportFactory.TRANSPORT_PROPERTY, "okhttp");
        try {
            WopError ex = assertThrows(WopError.class,
                    () -> TransportFactory.discover(TransportFactoryDiscoveryTest.class.getClassLoader()));
            assertTrue(ex.getMessage().contains("wop.transport=okhttp"), ex.getMessage());
            assertTrue(ex.getMessage().contains("alpha"), ex.getMessage());
        } finally {
            if (previous == null) {
                System.clearProperty(TransportFactory.TRANSPORT_PROPERTY);
            } else {
                System.setProperty(TransportFactory.TRANSPORT_PROPERTY, previous);
            }
        }
    }

    @Test
    void wopTransportInvalidValueListsAvailable(@TempDir Path tempDir) throws IOException {
        writeServices(tempDir, "com.wanlianyida.wop.TestAlphaTransportFactory\n"
                + "com.wanlianyida.wop.TestBetaTransportFactory\n");
        String previous = System.getProperty(TransportFactory.TRANSPORT_PROPERTY);
        System.setProperty(TransportFactory.TRANSPORT_PROPERTY, "missing");
        try (URLClassLoader multi = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                TransportFactoryDiscoveryTest.class.getClassLoader())) {
            WopError ex = assertThrows(WopError.class, () -> TransportFactory.discover(multi));
            assertTrue(ex.getMessage().contains("wop.transport=missing"), ex.getMessage());
            assertTrue(ex.getMessage().contains("alpha"), ex.getMessage());
        } finally {
            if (previous == null) {
                System.clearProperty(TransportFactory.TRANSPORT_PROPERTY);
            } else {
                System.setProperty(TransportFactory.TRANSPORT_PROPERTY, previous);
            }
        }
    }

    @Test
    void brokenRegistrationWrappedAsConfiguration(@TempDir Path tempDir) throws IOException {
        // 损坏态：注册项指向不存在的类，ServiceConfigurationError 必须包装为
        // WopError.configuration（含 cause），不让 JDK 原生错误越过 SPI 边界
        writeServices(tempDir, "com.example.NoSuchFactory\n");
        try (URLClassLoader broken = new URLClassLoader(new URL[]{tempDir.toUri().toURL()}, null)) {
            WopError ex = assertThrows(WopError.class, () -> TransportFactory.discover(broken));
            assertEquals(WopError.Category.configuration, ex.category());
            assertNotNull(ex.getCause());
        }
    }

    @Test
    void multiFactoriesFromTcclPropagateWithoutFallback(@TempDir Path tempDir) throws IOException {
        // 多态经无参 discover()：TCCL 命中多 factory → 错误原样上抛，
        // 不被「回退定义类加载器」掩盖（PR#35 评审：仅零结果触发回退）
        writeServices(tempDir, "com.wanlianyida.wop.TestAlphaTransportFactory\n"
                + "com.wanlianyida.wop.TestBetaTransportFactory\n");
        try (URLClassLoader multi = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                TransportFactoryDiscoveryTest.class.getClassLoader())) {
            Thread current = Thread.currentThread();
            ClassLoader original = current.getContextClassLoader();
            current.setContextClassLoader(multi);
            try {
                WopError ex = assertThrows(WopError.class, () -> TransportFactory.discover());
                assertEquals(WopError.Category.configuration, ex.category());
                assertTrue(ex.getMessage().contains("alpha"), ex.getMessage());
                assertTrue(ex.getMessage().contains("beta"), ex.getMessage());
            } finally {
                current.setContextClassLoader(original);
            }
        }
    }

    @Test
    void nameFailureWrappedAsConfiguration(@TempDir Path tempDir) throws IOException {
        // name() 抛错：多 factory 列名时单个注册项的运行时异常包装为
        // WopError.configuration（含 cause），与 ServiceLoader 加载失败的错误形状一致
        writeServices(tempDir, "com.wanlianyida.wop.TestAlphaTransportFactory\n"
                + "com.wanlianyida.wop.TestThrowingNameTransportFactory\n");
        try (URLClassLoader multi = new URLClassLoader(new URL[]{tempDir.toUri().toURL()},
                TransportFactoryDiscoveryTest.class.getClassLoader())) {
            WopError ex = assertThrows(WopError.class, () -> TransportFactory.discover(multi));
            assertEquals(WopError.Category.configuration, ex.category());
            assertTrue(ex.getMessage().contains("TestThrowingNameTransportFactory"), ex.getMessage());
            assertInstanceOf(IllegalStateException.class, ex.getCause());
        }
    }

    private static void writeServices(Path dir, String content) throws IOException {
        Path services = dir.resolve("META-INF/services");
        Files.createDirectories(services);
        Files.write(services.resolve(TransportFactory.class.getName()),
                content.getBytes(StandardCharsets.UTF_8));
    }
}

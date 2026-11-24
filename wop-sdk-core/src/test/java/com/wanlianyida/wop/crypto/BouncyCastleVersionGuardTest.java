package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;
import org.junit.jupiter.api.Test;

import java.security.Provider;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * jdk15on 发行线：BC 版本下限守卫（1.65）。
 * <p>
 * 消费者可能在自己的 pom 中声明更低的 bcprov-jdk15on 并因 Maven 就近优先胜出，
 * 此处必须 fail-fast 为明确的配置错误，而不是让下游抛 {@code NoSuchMethodError}。
 */
class BouncyCastleVersionGuardTest {

    @Test
    void rejectVersionBelowFloor() {
        WopError error = assertThrows(WopError.class,
                () -> BouncyCastleVersionGuard.requireSupportedVersion(1.5));
        assertEquals(WopError.Category.configuration, error.category());
        assertTrue(error.getMessage().contains("1.65"));
    }

    @Test
    void acceptFloorVersion() {
        assertDoesNotThrow(() -> BouncyCastleVersionGuard.requireSupportedVersion(1.65));
    }

    @Test
    void acceptNewerVersion() {
        assertDoesNotThrow(() -> BouncyCastleVersionGuard.requireSupportedVersion(1.70));
    }

    @Test
    void rejectProviderBelowFloor() {
        Provider old = new FakeProvider(1.5);
        WopError error = assertThrows(WopError.class,
                () -> BouncyCastleVersionGuard.requireSupported(old));
        assertEquals(WopError.Category.configuration, error.category());
    }

    @Test
    void acceptProviderAtFloor() {
        Provider provider = new FakeProvider(1.65);
        assertSame(provider, BouncyCastleVersionGuard.requireSupported(provider));
    }

    @Test
    void holderReturnsSingletonAboveFloor() {
        Provider provider = BouncyCastleHolder.provider();
        assertSame(provider, BouncyCastleHolder.provider());
        assertTrue(provider.getVersion() >= BouncyCastleVersionGuard.MIN_VERSION);
    }

    /** 测试用 Provider（protected 构造函数经子类访问）。 */
    private static final class FakeProvider extends Provider {

        private FakeProvider(double version) {
            super("WOP-TEST", version, "test provider");
        }
    }
}

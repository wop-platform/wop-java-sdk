package com.wanlianyida.wop.crypto;

import com.wanlianyida.wop.WopError;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * jdk15on 发行线：BC 版本下限守卫（1.65）。
 * <p>
 * 消费者可能在自己的 pom 中声明更低的 bcprov-jdk15on 并因 Maven 就近优先胜出，
 * 此处必须 fail-fast 为明确的配置错误，而不是让下游抛 NoSuchMethodError。
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
        assertEquals(1.65, BouncyCastleVersionGuard.requireSupportedVersion(1.65));
    }

    @Test
    void acceptNewerVersion() {
        assertEquals(1.70, BouncyCastleVersionGuard.requireSupportedVersion(1.70));
    }
}

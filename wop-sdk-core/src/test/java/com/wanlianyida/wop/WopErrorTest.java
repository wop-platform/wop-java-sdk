package com.wanlianyida.wop;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * WopError 契约（§2.2）：category 闭集七值、工厂双变体全覆盖、模糊文案精确断言。
 */
class WopErrorTest {

    // spec:2.2 —— category 闭集：小写 ASCII 逐值枚举（禁止自造取值）
    @Test
    void categoryClosedSetIsSevenLowercaseValues() {
        List<String> names = new ArrayList<>();
        for (WopError.Category category : WopError.Category.values()) {
            names.add(category.name());
        }
        assertEquals(Arrays.asList("configuration", "parse", "unsupported",
                "integrity", "consistency", "signature", "decrypt"), names,
                "闭集逐值且顺序恒定（跨语言契约）");
    }

    // spec:2.2 —— 明确文案类：message 变体
    @Test
    void clearMessageFactoriesCarryMessage() {
        assertEquals("配置缺失", WopError.configuration("配置缺失").getMessage());
        assertEquals("解析失败", WopError.parse("解析失败").getMessage());
        assertEquals("套件不支持", WopError.unsupported("套件不支持").getMessage());
        assertEquals("完整性失败", WopError.integrity("完整性失败").getMessage());
        assertEquals("一致性失败", WopError.consistency("一致性失败").getMessage());
    }

    // spec:2.2 —— 明确文案类：cause 变体（cause 必须透传）
    @Test
    void causeVariantsPropagateCause() {
        Throwable root = new IllegalStateException("root");
        assertSame(root, WopError.configuration("x", root).getCause());
        assertSame(root, WopError.parse("x", root).getCause());
        assertSame(root, WopError.unsupported("x", root).getCause());
        assertSame(root, WopError.integrity("x", root).getCause());
        assertSame(root, WopError.consistency("x", root).getCause());
    }

    // spec:2.2 —— 每个工厂的 category 全等（非 contains）
    @Test
    void factoriesExposeExactCategory() {
        assertEquals(WopError.Category.configuration, WopError.configuration("x").category());
        assertEquals(WopError.Category.parse, WopError.parse("x").category());
        assertEquals(WopError.Category.unsupported, WopError.unsupported("x").category());
        assertEquals(WopError.Category.integrity, WopError.integrity("x").category());
        assertEquals(WopError.Category.consistency, WopError.consistency("x").category());
        assertEquals(WopError.Category.signature, WopError.signature().category());
        assertEquals(WopError.Category.decrypt, WopError.decrypt().category());
    }

    // spec:2.2 —— 模糊文案：固定全文精确断言（防 oracle，禁止 contains）
    @Test
    void signatureFactoryUsesFixedOpaqueMessage() {
        assertEquals("签名验证失败", WopError.signature().getMessage());
    }

    @Test
    void decryptFactoryUsesFixedOpaqueMessage() {
        assertEquals("解密失败", WopError.decrypt().getMessage());
    }

    @Test
    void opaqueFactoriesHaveNoCause() {
        assertNull(WopError.signature().getCause());
        assertNull(WopError.decrypt().getCause());
    }
    // spec:2.2 —— 传输层保留异常（okhttp/jdkhttp/unirest 仍依赖）：构造器契约透传覆盖
    @Test
    void wopSdkExceptionConstructorsPropagate() {
        RuntimeException root = new IllegalStateException("root");
        assertEquals("m", new WopSdkException("m").getMessage());
        assertSame(root, new WopSdkException("m", root).getCause());
    }
}

package com.wanlianyida.wop.crypto.strategies;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CipherResult record→class 改写后的值语义契约（equals/hashCode/toString 按全部字段）。
 * 数组字段按引用比较（record 等价语义）。
 */
class StrategyValueSemanticsTest {

    @Test
    void cipherResultValueSemantics() {
        byte[] cipher = new byte[]{1};
        byte[] iv = new byte[]{2};
        CipherResult base = new CipherResult(cipher, iv);
        assertEquals(base, new CipherResult(cipher, iv));
        assertEquals(base.hashCode(), new CipherResult(cipher, iv).hashCode());
        assertEquals(base, base);
        assertNotEquals(base, null);
        assertNotEquals(base, (Object) "c");
        assertNotEquals(base, new CipherResult(new byte[]{9}, iv));
        assertNotEquals(base, new CipherResult(cipher, new byte[]{9}));
        assertTrue(base.toString().contains("cipher"));
    }
}

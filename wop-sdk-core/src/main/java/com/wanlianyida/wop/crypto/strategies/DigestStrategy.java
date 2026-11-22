package com.wanlianyida.wop.crypto.strategies;

public interface DigestStrategy {

    byte[] digest(byte[] data);

    String algorithmName();
}

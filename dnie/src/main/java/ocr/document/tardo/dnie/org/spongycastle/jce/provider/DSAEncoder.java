package org.spongycastle.jce.provider;

import java.io.IOException;
import java.math.BigInteger;

public interface DSAEncoder {
    BigInteger[] decode(byte[] bArr) throws IOException;

    byte[] encode(BigInteger bigInteger, BigInteger bigInteger2) throws IOException;
}

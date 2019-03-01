package org.spongycastle.asn1;

import java.io.IOException;

public class BERNull extends DERNull {
    public static final BERNull INSTANCE = new BERNull();

    void encode(DEROutputStream out) throws IOException {
        if ((out instanceof ASN1OutputStream) || (out instanceof BEROutputStream)) {
            out.write(5);
        } else {
            super.encode(out);
        }
    }
}

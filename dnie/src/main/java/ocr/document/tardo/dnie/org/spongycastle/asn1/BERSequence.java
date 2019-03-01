package org.spongycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

public class BERSequence extends DERSequence {
    public BERSequence(DEREncodable obj) {
        super(obj);
    }

    public BERSequence(ASN1EncodableVector v) {
        super(v);
    }

    void encode(DEROutputStream out) throws IOException {
        if ((out instanceof ASN1OutputStream) || (out instanceof BEROutputStream)) {
            out.write(48);
            out.write(128);
            Enumeration e = getObjects();
            while (e.hasMoreElements()) {
                out.writeObject(e.nextElement());
            }
            out.write(0);
            out.write(0);
            return;
        }
        super.encode(out);
    }
}

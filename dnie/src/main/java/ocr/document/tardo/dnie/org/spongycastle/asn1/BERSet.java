package org.spongycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

public class BERSet extends DERSet {
    public BERSet(DEREncodable obj) {
        super(obj);
    }

    public BERSet(ASN1EncodableVector v) {
        super(v, false);
    }

    BERSet(ASN1EncodableVector v, boolean needsSorting) {
        super(v, needsSorting);
    }

    void encode(DEROutputStream out) throws IOException {
        if ((out instanceof ASN1OutputStream) || (out instanceof BEROutputStream)) {
            out.write(49);
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

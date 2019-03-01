package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

public class DERSequence extends ASN1Sequence {
    public DERSequence(DEREncodable obj) {
        addObject(obj);
    }

    public DERSequence(ASN1EncodableVector v) {
        for (int i = 0; i != v.size(); i++) {
            addObject(v.get(i));
        }
    }

    public DERSequence(ASN1Encodable[] a) {
        for (int i = 0; i != a.length; i++) {
            addObject(a[i]);
        }
    }

    void encode(DEROutputStream out) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        Enumeration e = getObjects();
        while (e.hasMoreElements()) {
            dOut.writeObject(e.nextElement());
        }
        dOut.close();
        out.writeEncoded(48, bOut.toByteArray());
    }
}

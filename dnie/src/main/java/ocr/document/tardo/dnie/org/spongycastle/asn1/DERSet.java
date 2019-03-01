package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;

public class DERSet extends ASN1Set {
    public DERSet(DEREncodable obj) {
        addObject(obj);
    }

    public DERSet(ASN1EncodableVector v) {
        this(v, true);
    }

    public DERSet(ASN1Encodable[] a) {
        for (int i = 0; i != a.length; i++) {
            addObject(a[i]);
        }
        sort();
    }

    DERSet(ASN1EncodableVector v, boolean needsSorting) {
        for (int i = 0; i != v.size(); i++) {
            addObject(v.get(i));
        }
        if (needsSorting) {
            sort();
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
        out.writeEncoded(49, bOut.toByteArray());
    }
}

package org.spongycastle.asn1;

import java.util.Vector;

public class ASN1EncodableVector extends DEREncodableVector {
    /* renamed from: v */
    Vector f347v = new Vector();

    public void add(DEREncodable obj) {
        this.f347v.addElement(obj);
    }

    public DEREncodable get(int i) {
        return (DEREncodable) this.f347v.elementAt(i);
    }

    public int size() {
        return this.f347v.size();
    }
}

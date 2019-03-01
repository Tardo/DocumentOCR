package org.spongycastle.asn1;

import java.util.Vector;

public class DEREncodableVector {
    /* renamed from: v */
    Vector f151v = new Vector();

    public void add(DEREncodable obj) {
        this.f151v.addElement(obj);
    }

    public DEREncodable get(int i) {
        return (DEREncodable) this.f151v.elementAt(i);
    }

    public int size() {
        return this.f151v.size();
    }
}

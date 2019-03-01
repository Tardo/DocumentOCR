package org.spongycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

public class LazyDERSequence extends DERSequence {
    private byte[] encoded;
    private boolean parsed = false;
    private int size = -1;

    LazyDERSequence(byte[] encoded) throws IOException {
        this.encoded = encoded;
    }

    private void parse() {
        Enumeration en = new LazyDERConstructionEnumeration(this.encoded);
        while (en.hasMoreElements()) {
            addObject((DEREncodable) en.nextElement());
        }
        this.parsed = true;
    }

    public synchronized DEREncodable getObjectAt(int index) {
        if (!this.parsed) {
            parse();
        }
        return super.getObjectAt(index);
    }

    public synchronized Enumeration getObjects() {
        Enumeration objects;
        if (this.parsed) {
            objects = super.getObjects();
        } else {
            objects = new LazyDERConstructionEnumeration(this.encoded);
        }
        return objects;
    }

    public int size() {
        if (this.size < 0) {
            Enumeration en = new LazyDERConstructionEnumeration(this.encoded);
            this.size = 0;
            while (en.hasMoreElements()) {
                en.nextElement();
                this.size++;
            }
        }
        return this.size;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(48, this.encoded);
    }
}

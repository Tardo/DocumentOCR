package org.spongycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;

class LazyDERConstructionEnumeration implements Enumeration {
    private ASN1InputStream aIn;
    private Object nextObj = readObject();

    public LazyDERConstructionEnumeration(byte[] encoded) {
        this.aIn = new ASN1InputStream(encoded, true);
    }

    public boolean hasMoreElements() {
        return this.nextObj != null;
    }

    public Object nextElement() {
        Object o = this.nextObj;
        this.nextObj = readObject();
        return o;
    }

    private Object readObject() {
        try {
            return this.aIn.readObject();
        } catch (IOException e) {
            throw new ASN1ParsingException("malformed DER construction: " + e, e);
        }
    }
}

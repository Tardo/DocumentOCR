package org.spongycastle.asn1.x509;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;

public class X509ExtensionsGenerator {
    private Vector extOrdering = new Vector();
    private Hashtable extensions = new Hashtable();

    public void reset() {
        this.extensions = new Hashtable();
        this.extOrdering = new Vector();
    }

    public void addExtension(DERObjectIdentifier oid, boolean critical, DEREncodable value) {
        try {
            addExtension(oid, critical, value.getDERObject().getEncoded("DER"));
        } catch (IOException e) {
            throw new IllegalArgumentException("error encoding value: " + e);
        }
    }

    public void addExtension(DERObjectIdentifier oid, boolean critical, byte[] value) {
        if (this.extensions.containsKey(oid)) {
            throw new IllegalArgumentException("extension " + oid + " already added");
        }
        this.extOrdering.addElement(oid);
        this.extensions.put(oid, new X509Extension(critical, new DEROctetString(value)));
    }

    public boolean isEmpty() {
        return this.extOrdering.isEmpty();
    }

    public X509Extensions generate() {
        return new X509Extensions(this.extOrdering, this.extensions);
    }
}

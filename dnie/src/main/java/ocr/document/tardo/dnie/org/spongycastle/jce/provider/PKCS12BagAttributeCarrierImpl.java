package org.spongycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1OutputStream;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.jce.interfaces.PKCS12BagAttributeCarrier;

class PKCS12BagAttributeCarrierImpl implements PKCS12BagAttributeCarrier {
    private Hashtable pkcs12Attributes;
    private Vector pkcs12Ordering;

    PKCS12BagAttributeCarrierImpl(Hashtable attributes, Vector ordering) {
        this.pkcs12Attributes = attributes;
        this.pkcs12Ordering = ordering;
    }

    public PKCS12BagAttributeCarrierImpl() {
        this(new Hashtable(), new Vector());
    }

    public void setBagAttribute(DERObjectIdentifier oid, DEREncodable attribute) {
        if (this.pkcs12Attributes.containsKey(oid)) {
            this.pkcs12Attributes.put(oid, attribute);
            return;
        }
        this.pkcs12Attributes.put(oid, attribute);
        this.pkcs12Ordering.addElement(oid);
    }

    public DEREncodable getBagAttribute(DERObjectIdentifier oid) {
        return (DEREncodable) this.pkcs12Attributes.get(oid);
    }

    public Enumeration getBagAttributeKeys() {
        return this.pkcs12Ordering.elements();
    }

    int size() {
        return this.pkcs12Ordering.size();
    }

    Hashtable getAttributes() {
        return this.pkcs12Attributes;
    }

    Vector getOrdering() {
        return this.pkcs12Ordering;
    }

    public void writeObject(ObjectOutputStream out) throws IOException {
        if (this.pkcs12Ordering.size() == 0) {
            out.writeObject(new Hashtable());
            out.writeObject(new Vector());
            return;
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);
        Enumeration e = getBagAttributeKeys();
        while (e.hasMoreElements()) {
            DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
            aOut.writeObject(oid);
            aOut.writeObject(this.pkcs12Attributes.get(oid));
        }
        out.writeObject(bOut.toByteArray());
    }

    public void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        Object obj = in.readObject();
        if (obj instanceof Hashtable) {
            this.pkcs12Attributes = (Hashtable) obj;
            this.pkcs12Ordering = (Vector) in.readObject();
            return;
        }
        ASN1InputStream aIn = new ASN1InputStream((byte[]) obj);
        while (true) {
            DERObjectIdentifier oid = (DERObjectIdentifier) aIn.readObject();
            if (oid != null) {
                setBagAttribute(oid, aIn.readObject());
            } else {
                return;
            }
        }
    }
}

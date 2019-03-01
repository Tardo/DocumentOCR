package org.spongycastle.asn1.ess;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;

public class ContentIdentifier extends ASN1Encodable {
    ASN1OctetString value;

    public static ContentIdentifier getInstance(Object o) {
        if (o == null || (o instanceof ContentIdentifier)) {
            return (ContentIdentifier) o;
        }
        if (o instanceof ASN1OctetString) {
            return new ContentIdentifier((ASN1OctetString) o);
        }
        throw new IllegalArgumentException("unknown object in 'ContentIdentifier' factory : " + o.getClass().getName() + ".");
    }

    public ContentIdentifier(ASN1OctetString value) {
        this.value = value;
    }

    public ContentIdentifier(byte[] value) {
        this(new DEROctetString(value));
    }

    public ASN1OctetString getValue() {
        return this.value;
    }

    public DERObject toASN1Object() {
        return this.value;
    }
}

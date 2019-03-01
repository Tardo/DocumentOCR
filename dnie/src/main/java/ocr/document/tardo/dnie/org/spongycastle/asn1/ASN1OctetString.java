package org.spongycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Hex;

public abstract class ASN1OctetString extends ASN1Object implements ASN1OctetStringParser {
    byte[] string;

    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public static ASN1OctetString getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof ASN1OctetString)) {
            return getInstance(o);
        }
        return BERConstructedOctetString.fromSequence(ASN1Sequence.getInstance(o));
    }

    public static ASN1OctetString getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1OctetString)) {
            return (ASN1OctetString) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return getInstance(((ASN1TaggedObject) obj).getObject());
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public ASN1OctetString(byte[] string) {
        if (string == null) {
            throw new NullPointerException("string cannot be null");
        }
        this.string = string;
    }

    public ASN1OctetString(DEREncodable obj) {
        try {
            this.string = obj.getDERObject().getEncoded("DER");
        } catch (IOException e) {
            throw new IllegalArgumentException("Error processing object : " + e.toString());
        }
    }

    public InputStream getOctetStream() {
        return new ByteArrayInputStream(this.string);
    }

    public ASN1OctetStringParser parser() {
        return this;
    }

    public byte[] getOctets() {
        return this.string;
    }

    public int hashCode() {
        return Arrays.hashCode(getOctets());
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof ASN1OctetString)) {
            return false;
        }
        return Arrays.areEqual(this.string, ((ASN1OctetString) o).string);
    }

    public DERObject getLoadedObject() {
        return getDERObject();
    }

    public String toString() {
        return "#" + new String(Hex.encode(this.string));
    }
}

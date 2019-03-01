package org.spongycastle.asn1.x500;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBMPString;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERT61String;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.DERUniversalString;

public class DirectoryString extends ASN1Encodable implements ASN1Choice, ASN1String {
    private ASN1String string;

    public static DirectoryString getInstance(Object o) {
        if (o instanceof DirectoryString) {
            return (DirectoryString) o;
        }
        if (o instanceof DERT61String) {
            return new DirectoryString((DERT61String) o);
        }
        if (o instanceof DERPrintableString) {
            return new DirectoryString((DERPrintableString) o);
        }
        if (o instanceof DERUniversalString) {
            return new DirectoryString((DERUniversalString) o);
        }
        if (o instanceof DERUTF8String) {
            return new DirectoryString((DERUTF8String) o);
        }
        if (o instanceof DERBMPString) {
            return new DirectoryString((DERBMPString) o);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + o.getClass().getName());
    }

    public static DirectoryString getInstance(ASN1TaggedObject o, boolean explicit) {
        if (explicit) {
            return getInstance(o.getObject());
        }
        throw new IllegalArgumentException("choice item must be explicitly tagged");
    }

    private DirectoryString(DERT61String string) {
        this.string = string;
    }

    private DirectoryString(DERPrintableString string) {
        this.string = string;
    }

    private DirectoryString(DERUniversalString string) {
        this.string = string;
    }

    private DirectoryString(DERUTF8String string) {
        this.string = string;
    }

    private DirectoryString(DERBMPString string) {
        this.string = string;
    }

    public DirectoryString(String string) {
        this.string = new DERUTF8String(string);
    }

    public String getString() {
        return this.string.getString();
    }

    public String toString() {
        return this.string.getString();
    }

    public DERObject toASN1Object() {
        return ((DEREncodable) this.string).getDERObject();
    }
}
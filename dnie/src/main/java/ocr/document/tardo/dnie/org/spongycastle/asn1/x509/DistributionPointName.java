package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class DistributionPointName extends ASN1Encodable implements ASN1Choice {
    public static final int FULL_NAME = 0;
    public static final int NAME_RELATIVE_TO_CRL_ISSUER = 1;
    DEREncodable name;
    int type;

    public static DistributionPointName getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1TaggedObject.getInstance(obj, true));
    }

    public static DistributionPointName getInstance(Object obj) {
        if (obj == null || (obj instanceof DistributionPointName)) {
            return (DistributionPointName) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new DistributionPointName((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public DistributionPointName(int type, DEREncodable name) {
        this.type = type;
        this.name = name;
    }

    public DistributionPointName(int type, ASN1Encodable name) {
        this.type = type;
        this.name = name;
    }

    public DistributionPointName(GeneralNames name) {
        this(0, (ASN1Encodable) name);
    }

    public int getType() {
        return this.type;
    }

    public ASN1Encodable getName() {
        return (ASN1Encodable) this.name;
    }

    public DistributionPointName(ASN1TaggedObject obj) {
        this.type = obj.getTagNo();
        if (this.type == 0) {
            this.name = GeneralNames.getInstance(obj, false);
        } else {
            this.name = ASN1Set.getInstance(obj, false);
        }
    }

    public DERObject toASN1Object() {
        return new DERTaggedObject(false, this.type, this.name);
    }

    public String toString() {
        String sep = System.getProperty("line.separator");
        StringBuffer buf = new StringBuffer();
        buf.append("DistributionPointName: [");
        buf.append(sep);
        if (this.type == 0) {
            appendObject(buf, sep, "fullName", this.name.toString());
        } else {
            appendObject(buf, sep, "nameRelativeToCRLIssuer", this.name.toString());
        }
        buf.append("]");
        buf.append(sep);
        return buf.toString();
    }

    private void appendObject(StringBuffer buf, String sep, String name, String value) {
        String indent = "    ";
        buf.append(indent);
        buf.append(name);
        buf.append(":");
        buf.append(sep);
        buf.append(indent);
        buf.append(indent);
        buf.append(value);
        buf.append(sep);
    }
}

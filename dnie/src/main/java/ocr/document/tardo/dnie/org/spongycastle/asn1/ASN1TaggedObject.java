package org.spongycastle.asn1;

import java.io.IOException;

public abstract class ASN1TaggedObject extends ASN1Object implements ASN1TaggedObjectParser {
    boolean empty;
    boolean explicit;
    DEREncodable obj;
    int tagNo;

    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public static ASN1TaggedObject getInstance(ASN1TaggedObject obj, boolean explicit) {
        if (explicit) {
            return (ASN1TaggedObject) obj.getObject();
        }
        throw new IllegalArgumentException("implicitly tagged tagged object");
    }

    public static ASN1TaggedObject getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1TaggedObject)) {
            return (ASN1TaggedObject) obj;
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public ASN1TaggedObject(int tagNo, DEREncodable obj) {
        this.empty = false;
        this.explicit = true;
        this.obj = null;
        this.explicit = true;
        this.tagNo = tagNo;
        this.obj = obj;
    }

    public ASN1TaggedObject(boolean explicit, int tagNo, DEREncodable obj) {
        this.empty = false;
        this.explicit = true;
        this.obj = null;
        if (obj instanceof ASN1Choice) {
            this.explicit = true;
        } else {
            this.explicit = explicit;
        }
        this.tagNo = tagNo;
        this.obj = obj;
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof ASN1TaggedObject)) {
            return false;
        }
        ASN1TaggedObject other = (ASN1TaggedObject) o;
        if (this.tagNo != other.tagNo || this.empty != other.empty || this.explicit != other.explicit) {
            return false;
        }
        if (this.obj == null) {
            if (other.obj != null) {
                return false;
            }
        } else if (!this.obj.getDERObject().equals(other.obj.getDERObject())) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        int code = this.tagNo;
        if (this.obj != null) {
            return code ^ this.obj.hashCode();
        }
        return code;
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public boolean isExplicit() {
        return this.explicit;
    }

    public boolean isEmpty() {
        return this.empty;
    }

    public DERObject getObject() {
        if (this.obj != null) {
            return this.obj.getDERObject();
        }
        return null;
    }

    public DEREncodable getObjectParser(int tag, boolean isExplicit) {
        switch (tag) {
            case 4:
                return ASN1OctetString.getInstance(this, isExplicit).parser();
            case 16:
                return ASN1Sequence.getInstance(this, isExplicit).parser();
            case 17:
                return ASN1Set.getInstance(this, isExplicit).parser();
            default:
                if (isExplicit) {
                    return getObject();
                }
                throw new RuntimeException("implicit tagging not implemented for tag: " + tag);
        }
    }

    public DERObject getLoadedObject() {
        return getDERObject();
    }

    public String toString() {
        return "[" + this.tagNo + "]" + this.obj;
    }
}

package org.spongycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

public abstract class ASN1Sequence extends ASN1Object {
    private Vector seq = new Vector();

    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public static ASN1Sequence getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Sequence)) {
            return (ASN1Sequence) obj;
        }
        if (obj instanceof byte[]) {
            try {
                return getInstance(ASN1Object.fromByteArray((byte[]) obj));
            } catch (IOException e) {
                throw new IllegalArgumentException("failed to construct sequence from byte[]: " + e.getMessage());
            }
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1Sequence getInstance(ASN1TaggedObject obj, boolean explicit) {
        if (explicit) {
            if (obj.isExplicit()) {
                return (ASN1Sequence) obj.getObject();
            }
            throw new IllegalArgumentException("object implicit - explicit expected.");
        } else if (obj.isExplicit()) {
            if (obj instanceof BERTaggedObject) {
                return new BERSequence(obj.getObject());
            }
            return new DERSequence(obj.getObject());
        } else if (obj.getObject() instanceof ASN1Sequence) {
            return (ASN1Sequence) obj.getObject();
        } else {
            throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
        }
    }

    public Enumeration getObjects() {
        return this.seq.elements();
    }

    public ASN1SequenceParser parser() {
        final ASN1Sequence outer = this;
        return new ASN1SequenceParser() {
            private int index;
            private final int max = ASN1Sequence.this.size();

            public DEREncodable readObject() throws IOException {
                if (this.index == this.max) {
                    return null;
                }
                ASN1Sequence aSN1Sequence = ASN1Sequence.this;
                int i = this.index;
                this.index = i + 1;
                DEREncodable obj = aSN1Sequence.getObjectAt(i);
                if (obj instanceof ASN1Sequence) {
                    return ((ASN1Sequence) obj).parser();
                }
                if (obj instanceof ASN1Set) {
                    return ((ASN1Set) obj).parser();
                }
                return obj;
            }

            public DERObject getLoadedObject() {
                return outer;
            }

            public DERObject getDERObject() {
                return outer;
            }
        };
    }

    public DEREncodable getObjectAt(int index) {
        return (DEREncodable) this.seq.elementAt(index);
    }

    public int size() {
        return this.seq.size();
    }

    public int hashCode() {
        Enumeration e = getObjects();
        int hashCode = size();
        while (e.hasMoreElements()) {
            hashCode = (hashCode * 17) ^ getNext(e).hashCode();
        }
        return hashCode;
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof ASN1Sequence)) {
            return false;
        }
        ASN1Sequence other = (ASN1Sequence) o;
        if (size() != other.size()) {
            return false;
        }
        Enumeration s1 = getObjects();
        Enumeration s2 = other.getObjects();
        while (s1.hasMoreElements()) {
            DEREncodable obj1 = getNext(s1);
            DEREncodable obj2 = getNext(s2);
            DERObject o1 = obj1.getDERObject();
            DERObject o2 = obj2.getDERObject();
            if (o1 != o2) {
                if (!o1.equals(o2)) {
                    return false;
                }
            }
        }
        return true;
    }

    private DEREncodable getNext(Enumeration e) {
        DEREncodable encObj = (DEREncodable) e.nextElement();
        if (encObj == null) {
            return DERNull.INSTANCE;
        }
        return encObj;
    }

    protected void addObject(DEREncodable obj) {
        this.seq.addElement(obj);
    }

    public String toString() {
        return this.seq.toString();
    }
}

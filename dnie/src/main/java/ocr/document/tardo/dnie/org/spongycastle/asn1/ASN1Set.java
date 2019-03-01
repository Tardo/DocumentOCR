package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

public abstract class ASN1Set extends ASN1Object {
    protected Vector set = new Vector();

    abstract void encode(DEROutputStream dEROutputStream) throws IOException;

    public static ASN1Set getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Set)) {
            return (ASN1Set) obj;
        }
        throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1Set getInstance(ASN1TaggedObject obj, boolean explicit) {
        if (explicit) {
            if (obj.isExplicit()) {
                return (ASN1Set) obj.getObject();
            }
            throw new IllegalArgumentException("object implicit - explicit expected.");
        } else if (obj.isExplicit()) {
            return new DERSet(obj.getObject());
        } else {
            if (obj.getObject() instanceof ASN1Set) {
                return (ASN1Set) obj.getObject();
            }
            ASN1EncodableVector v = new ASN1EncodableVector();
            if (obj.getObject() instanceof ASN1Sequence) {
                Enumeration e = ((ASN1Sequence) obj.getObject()).getObjects();
                while (e.hasMoreElements()) {
                    v.add((DEREncodable) e.nextElement());
                }
                return new DERSet(v, false);
            }
            throw new IllegalArgumentException("unknown object in getInstance: " + obj.getClass().getName());
        }
    }

    public Enumeration getObjects() {
        return this.set.elements();
    }

    public DEREncodable getObjectAt(int index) {
        return (DEREncodable) this.set.elementAt(index);
    }

    public int size() {
        return this.set.size();
    }

    public ASN1Encodable[] toArray() {
        ASN1Encodable[] values = new ASN1Encodable[size()];
        for (int i = 0; i != size(); i++) {
            values[i] = (ASN1Encodable) getObjectAt(i);
        }
        return values;
    }

    public ASN1SetParser parser() {
        final ASN1Set outer = this;
        return new ASN1SetParser() {
            private int index;
            private final int max = ASN1Set.this.size();

            public DEREncodable readObject() throws IOException {
                if (this.index == this.max) {
                    return null;
                }
                ASN1Set aSN1Set = ASN1Set.this;
                int i = this.index;
                this.index = i + 1;
                DEREncodable obj = aSN1Set.getObjectAt(i);
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

    public int hashCode() {
        Enumeration e = getObjects();
        int hashCode = size();
        while (e.hasMoreElements()) {
            hashCode = (hashCode * 17) ^ getNext(e).hashCode();
        }
        return hashCode;
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof ASN1Set)) {
            return false;
        }
        ASN1Set other = (ASN1Set) o;
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

    private boolean lessThanOrEqual(byte[] a, byte[] b) {
        int len = Math.min(a.length, b.length);
        int i = 0;
        while (i != len) {
            if (a[i] == b[i]) {
                i++;
            } else if ((a[i] & 255) < (b[i] & 255)) {
                return true;
            } else {
                return false;
            }
        }
        if (len != a.length) {
            return false;
        }
        return true;
    }

    private byte[] getEncoded(DEREncodable obj) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try {
            new ASN1OutputStream(bOut).writeObject(obj);
            return bOut.toByteArray();
        } catch (IOException e) {
            throw new IllegalArgumentException("cannot encode object added to SET");
        }
    }

    protected void sort() {
        if (this.set.size() > 1) {
            boolean swapped = true;
            int lastSwap = this.set.size() - 1;
            while (swapped) {
                int swapIndex = 0;
                byte[] a = getEncoded((DEREncodable) this.set.elementAt(0));
                swapped = false;
                for (int index = 0; index != lastSwap; index++) {
                    byte[] b = getEncoded((DEREncodable) this.set.elementAt(index + 1));
                    if (lessThanOrEqual(a, b)) {
                        a = b;
                    } else {
                        Object o = this.set.elementAt(index);
                        this.set.setElementAt(this.set.elementAt(index + 1), index);
                        this.set.setElementAt(o, index + 1);
                        swapped = true;
                        swapIndex = index;
                    }
                }
                lastSwap = swapIndex;
            }
        }
    }

    protected void addObject(DEREncodable obj) {
        this.set.addElement(obj);
    }

    public String toString() {
        return this.set.toString();
    }
}

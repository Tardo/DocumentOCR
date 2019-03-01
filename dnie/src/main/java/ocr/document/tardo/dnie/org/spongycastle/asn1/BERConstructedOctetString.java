package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Vector;

public class BERConstructedOctetString extends DEROctetString {
    private static final int MAX_LENGTH = 1000;
    private Vector octs;

    private static byte[] toBytes(Vector octs) {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int i = 0;
        while (i != octs.size()) {
            try {
                bOut.write(((DEROctetString) octs.elementAt(i)).getOctets());
                i++;
            } catch (ClassCastException e) {
                throw new IllegalArgumentException(octs.elementAt(i).getClass().getName() + " found in input should only contain DEROctetString");
            } catch (IOException e2) {
                throw new IllegalArgumentException("exception converting octets " + e2.toString());
            }
        }
        return bOut.toByteArray();
    }

    public BERConstructedOctetString(byte[] string) {
        super(string);
    }

    public BERConstructedOctetString(Vector octs) {
        super(toBytes(octs));
        this.octs = octs;
    }

    public BERConstructedOctetString(DERObject obj) {
        super((DEREncodable) obj);
    }

    public BERConstructedOctetString(DEREncodable obj) {
        super(obj.getDERObject());
    }

    public byte[] getOctets() {
        return this.string;
    }

    public Enumeration getObjects() {
        if (this.octs == null) {
            return generateOcts().elements();
        }
        return this.octs.elements();
    }

    private Vector generateOcts() {
        Vector vec = new Vector();
        for (int i = 0; i < this.string.length; i += MAX_LENGTH) {
            int end;
            if (i + MAX_LENGTH > this.string.length) {
                end = this.string.length;
            } else {
                end = i + MAX_LENGTH;
            }
            byte[] nStr = new byte[(end - i)];
            System.arraycopy(this.string, i, nStr, 0, nStr.length);
            vec.addElement(new DEROctetString(nStr));
        }
        return vec;
    }

    public void encode(DEROutputStream out) throws IOException {
        if ((out instanceof ASN1OutputStream) || (out instanceof BEROutputStream)) {
            out.write(36);
            out.write(128);
            Enumeration e = getObjects();
            while (e.hasMoreElements()) {
                out.writeObject(e.nextElement());
            }
            out.write(0);
            out.write(0);
            return;
        }
        super.encode(out);
    }

    public static BERConstructedOctetString fromSequence(ASN1Sequence seq) {
        Vector v = new Vector();
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            v.addElement(e.nextElement());
        }
        return new BERConstructedOctetString(v);
    }
}

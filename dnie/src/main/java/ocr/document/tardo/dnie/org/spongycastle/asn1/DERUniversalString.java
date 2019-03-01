package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import jj2000.j2k.codestream.reader.BitstreamReaderAgent;
import jj2000.j2k.entropy.decoder.EntropyDecoder;

public class DERUniversalString extends ASN1Object implements DERString {
    private static final char[] table = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', BitstreamReaderAgent.OPT_PREFIX, EntropyDecoder.OPT_PREFIX, 'D', 'E', 'F'};
    private byte[] string;

    public static DERUniversalString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUniversalString)) {
            return (DERUniversalString) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERUniversalString getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERUniversalString)) {
            return getInstance(o);
        }
        return new DERUniversalString(((ASN1OctetString) o).getOctets());
    }

    public DERUniversalString(byte[] string) {
        this.string = string;
    }

    public String getString() {
        StringBuffer buf = new StringBuffer("#");
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try {
            new ASN1OutputStream(bOut).writeObject(this);
            byte[] string = bOut.toByteArray();
            for (int i = 0; i != string.length; i++) {
                buf.append(table[(string[i] >>> 4) & 15]);
                buf.append(table[string[i] & 15]);
            }
            return buf.toString();
        } catch (IOException e) {
            throw new RuntimeException("internal error encoding BitString");
        }
    }

    public String toString() {
        return getString();
    }

    public byte[] getOctets() {
        return this.string;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(28, getOctets());
    }

    boolean asn1Equals(DERObject o) {
        if (o instanceof DERUniversalString) {
            return getString().equals(((DERUniversalString) o).getString());
        }
        return false;
    }

    public int hashCode() {
        return getString().hashCode();
    }
}

package org.spongycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.pqc.math.linearalgebra.Matrix;

public class DERPrintableString extends ASN1Object implements DERString {
    String string;

    public static DERPrintableString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERPrintableString)) {
            return (DERPrintableString) obj;
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static DERPrintableString getInstance(ASN1TaggedObject obj, boolean explicit) {
        DERObject o = obj.getObject();
        if (explicit || (o instanceof DERPrintableString)) {
            return getInstance(o);
        }
        return new DERPrintableString(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERPrintableString(byte[] string) {
        char[] cs = new char[string.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (string[i] & 255);
        }
        this.string = new String(cs);
    }

    public DERPrintableString(String string) {
        this(string, false);
    }

    public DERPrintableString(String string, boolean validate) {
        if (!validate || isPrintableString(string)) {
            this.string = string;
            return;
        }
        throw new IllegalArgumentException("string contains illegal characters");
    }

    public String getString() {
        return this.string;
    }

    public byte[] getOctets() {
        char[] cs = this.string.toCharArray();
        byte[] bs = new byte[cs.length];
        for (int i = 0; i != cs.length; i++) {
            bs[i] = (byte) cs[i];
        }
        return bs;
    }

    void encode(DEROutputStream out) throws IOException {
        out.writeEncoded(19, getOctets());
    }

    public int hashCode() {
        return getString().hashCode();
    }

    boolean asn1Equals(DERObject o) {
        if (!(o instanceof DERPrintableString)) {
            return false;
        }
        return getString().equals(((DERPrintableString) o).getString());
    }

    public String toString() {
        return this.string;
    }

    public static boolean isPrintableString(String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            char ch = str.charAt(i);
            if (ch > '') {
                return false;
            }
            if (('a' > ch || ch > 'z') && (('A' > ch || ch > Matrix.MATRIX_TYPE_ZERO) && ('0' > ch || ch > '9'))) {
                switch (ch) {
                    case ' ':
                    case '\'':
                    case JPAKEParticipant.STATE_ROUND_2_VALIDATED /*40*/:
                    case EACTags.INTERCHANGE_PROFILE /*41*/:
                    case '+':
                    case ',':
                    case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
                    case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA /*46*/:
                    case '/':
                    case ':':
                    case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256 /*61*/:
                    case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256 /*63*/:
                        break;
                    default:
                        return false;
                }
            }
        }
        return true;
    }
}

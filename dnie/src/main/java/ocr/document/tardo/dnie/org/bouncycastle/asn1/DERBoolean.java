package org.bouncycastle.asn1;

import com.jcraft.jzlib.GZIPHeader;
import java.io.IOException;
import org.bouncycastle.util.Arrays;

public class DERBoolean extends ASN1Primitive {
    public static final ASN1Boolean FALSE = new ASN1Boolean(false);
    private static final byte[] FALSE_VALUE = new byte[]{(byte) 0};
    public static final ASN1Boolean TRUE = new ASN1Boolean(true);
    private static final byte[] TRUE_VALUE = new byte[]{(byte) -1};
    private byte[] value;

    public DERBoolean(boolean z) {
        this.value = z ? TRUE_VALUE : FALSE_VALUE;
    }

    DERBoolean(byte[] bArr) {
        if (bArr.length != 1) {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        } else if (bArr[0] == (byte) 0) {
            this.value = FALSE_VALUE;
        } else if (bArr[0] == GZIPHeader.OS_UNKNOWN) {
            this.value = TRUE_VALUE;
        } else {
            this.value = Arrays.clone(bArr);
        }
    }

    static ASN1Boolean fromOctetString(byte[] bArr) {
        if (bArr.length == 1) {
            return bArr[0] == (byte) 0 ? FALSE : bArr[0] == GZIPHeader.OS_UNKNOWN ? TRUE : new ASN1Boolean(bArr);
        } else {
            throw new IllegalArgumentException("byte value should have 1 byte in it");
        }
    }

    public static ASN1Boolean getInstance(int i) {
        return i != 0 ? TRUE : FALSE;
    }

    public static ASN1Boolean getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1Boolean)) {
            return (ASN1Boolean) obj;
        }
        if (obj instanceof DERBoolean) {
            return ((DERBoolean) obj).isTrue() ? TRUE : FALSE;
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static ASN1Boolean getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        Object object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERBoolean)) ? getInstance(object) : fromOctetString(((ASN1OctetString) object).getOctets());
    }

    public static ASN1Boolean getInstance(boolean z) {
        return z ? TRUE : FALSE;
    }

    protected boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        return aSN1Primitive != null && (aSN1Primitive instanceof DERBoolean) && this.value[0] == ((DERBoolean) aSN1Primitive).value[0];
    }

    void encode(ASN1OutputStream aSN1OutputStream) throws IOException {
        aSN1OutputStream.writeEncoded(1, this.value);
    }

    int encodedLength() {
        return 3;
    }

    public int hashCode() {
        return this.value[0];
    }

    boolean isConstructed() {
        return false;
    }

    public boolean isTrue() {
        return this.value[0] != (byte) 0;
    }

    public String toString() {
        return this.value[0] != (byte) 0 ? "TRUE" : "FALSE";
    }
}

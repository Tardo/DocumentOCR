package org.spongycastle.asn1.x509;

import org.spongycastle.asn1.DERBitString;

public class KeyUsage extends DERBitString {
    public static final int cRLSign = 2;
    public static final int dataEncipherment = 16;
    public static final int decipherOnly = 32768;
    public static final int digitalSignature = 128;
    public static final int encipherOnly = 1;
    public static final int keyAgreement = 8;
    public static final int keyCertSign = 4;
    public static final int keyEncipherment = 32;
    public static final int nonRepudiation = 64;

    public static DERBitString getInstance(Object obj) {
        if (obj instanceof KeyUsage) {
            return (KeyUsage) obj;
        }
        if (obj instanceof X509Extension) {
            return new KeyUsage(DERBitString.getInstance(X509Extension.convertValueToObject((X509Extension) obj)));
        }
        return new KeyUsage(DERBitString.getInstance(obj));
    }

    public KeyUsage(int usage) {
        super(DERBitString.getBytes(usage), DERBitString.getPadBits(usage));
    }

    public KeyUsage(DERBitString usage) {
        super(usage.getBytes(), usage.getPadBits());
    }

    public String toString() {
        if (this.data.length == 1) {
            return "KeyUsage: 0x" + Integer.toHexString(this.data[0] & 255);
        }
        return "KeyUsage: 0x" + Integer.toHexString(((this.data[1] & 255) << 8) | (this.data[0] & 255));
    }
}

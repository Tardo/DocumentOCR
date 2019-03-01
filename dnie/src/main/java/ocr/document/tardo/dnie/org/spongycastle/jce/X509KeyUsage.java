package org.spongycastle.jce;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.x509.KeyUsage;

public class X509KeyUsage extends ASN1Encodable {
    public static final int cRLSign = 2;
    public static final int dataEncipherment = 16;
    public static final int decipherOnly = 32768;
    public static final int digitalSignature = 128;
    public static final int encipherOnly = 1;
    public static final int keyAgreement = 8;
    public static final int keyCertSign = 4;
    public static final int keyEncipherment = 32;
    public static final int nonRepudiation = 64;
    private int usage = 0;

    public X509KeyUsage(int usage) {
        this.usage = usage;
    }

    public DERObject toASN1Object() {
        return new KeyUsage(this.usage);
    }
}

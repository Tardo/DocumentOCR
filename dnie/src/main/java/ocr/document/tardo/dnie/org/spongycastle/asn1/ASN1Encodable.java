package org.spongycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public abstract class ASN1Encodable implements DEREncodable {
    public static final String BER = "BER";
    public static final String DER = "DER";

    public abstract DERObject toASN1Object();

    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new ASN1OutputStream(bOut).writeObject(this);
        return bOut.toByteArray();
    }

    public byte[] getEncoded(String encoding) throws IOException {
        if (!encoding.equals("DER")) {
            return getEncoded();
        }
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new DEROutputStream(bOut).writeObject(this);
        return bOut.toByteArray();
    }

    public byte[] getDEREncoded() {
        try {
            return getEncoded("DER");
        } catch (IOException e) {
            return null;
        }
    }

    public int hashCode() {
        return toASN1Object().hashCode();
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DEREncodable)) {
            return false;
        }
        return toASN1Object().equals(((DEREncodable) o).getDERObject());
    }

    public DERObject getDERObject() {
        return toASN1Object();
    }
}

package de.tsenger.androsmex.iso7816;

import java.io.IOException;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

public class DO99 {
    private byte[] data = null;
    private DERTaggedObject to = null;

    public DO99(byte[] le) {
        this.data = (byte[]) le.clone();
        this.to = new DERTaggedObject(false, 25, new DEROctetString(le));
    }

    public void fromByteArray(byte[] encodedData) {
        ASN1InputStream asn1in = new ASN1InputStream(encodedData);
        try {
            this.to = (DERTaggedObject) asn1in.readObject();
            asn1in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.data = ((DEROctetString) this.to.getObject()).getOctets();
    }

    public byte[] getEncoded() {
        try {
            return this.to.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getData() {
        return this.data;
    }
}

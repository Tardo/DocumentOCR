package de.tsenger.androsmex.iso7816;

import java.io.IOException;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

public class DO8E {
    private byte[] data = null;
    private DERTaggedObject to = null;

    public DO8E(byte[] checksum) {
        this.data = (byte[]) checksum.clone();
        this.to = new DERTaggedObject(false, 14, new DEROctetString(checksum));
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

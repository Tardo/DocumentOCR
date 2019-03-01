package de.tsenger.androsmex.iso7816;

import java.io.IOException;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

public class DO97 {
    private byte[] data;
    private DERTaggedObject to;

    public DO97() {
        this.data = null;
        this.to = null;
    }

    public DO97(byte[] le) {
        this.data = null;
        this.to = null;
        this.data = (byte[]) le.clone();
        this.to = new DERTaggedObject(false, 23, new DEROctetString(this.data));
    }

    public DO97(int le) {
        this.data = null;
        this.to = null;
        this.data = new byte[1];
        this.data[0] = (byte) le;
        this.to = new DERTaggedObject(false, 23, new DEROctetString(this.data));
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

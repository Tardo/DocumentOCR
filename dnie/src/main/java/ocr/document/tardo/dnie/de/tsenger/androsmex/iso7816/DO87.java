package de.tsenger.androsmex.iso7816;

import java.io.IOException;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

public class DO87 {
    private byte[] data = null;
    private DERTaggedObject to = null;
    private byte[] value_ = null;

    public DO87(byte[] data) {
        this.data = (byte[]) data.clone();
        this.value_ = addOne(data);
        this.to = new DERTaggedObject(false, 7, new DEROctetString(this.value_));
    }

    private byte[] addOne(byte[] data) {
        byte[] ret = new byte[(data.length + 1)];
        System.arraycopy(data, 0, ret, 1, data.length);
        ret[0] = (byte) 1;
        return ret;
    }

    private byte[] removeOne(byte[] value) {
        byte[] ret = new byte[(value.length - 1)];
        System.arraycopy(value, 1, ret, 0, ret.length);
        return ret;
    }

    public void fromByteArray(byte[] encodedData) {
        ASN1InputStream asn1in = new ASN1InputStream(encodedData);
        try {
            this.to = (DERTaggedObject) asn1in.readObject();
            asn1in.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.value_ = ((DEROctetString) this.to.getObject()).getOctets();
        this.data = removeOne(this.value_);
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

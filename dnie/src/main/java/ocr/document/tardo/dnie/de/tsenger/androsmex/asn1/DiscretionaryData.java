package de.tsenger.androsmex.asn1;

import java.io.IOException;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;

public class DiscretionaryData extends ASN1Encodable {
    private DEROctetString data = null;

    public DiscretionaryData(byte[] data) {
        this.data = new DEROctetString(data);
    }

    public DiscretionaryData(byte data) {
        this.data = new DEROctetString(new byte[]{data});
    }

    public DERObject toASN1Object() {
        try {
            return new DERApplicationSpecific(false, 19, this.data);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] getData() {
        return this.data.getOctets();
    }
}

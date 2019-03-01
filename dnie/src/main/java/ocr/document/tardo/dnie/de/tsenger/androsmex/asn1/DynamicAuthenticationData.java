package de.tsenger.androsmex.asn1;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

public class DynamicAuthenticationData extends ASN1Encodable {
    private final List<DERTaggedObject> objects = new ArrayList(3);

    public DynamicAuthenticationData(byte[] data) {
        ASN1Sequence seq = null;
        try {
            seq = ASN1Sequence.getInstance(((DERApplicationSpecific) ASN1Object.fromByteArray(data)).getObject(16));
        } catch (IOException e) {
            e.printStackTrace();
        }
        for (int i = 0; i < seq.size(); i++) {
            this.objects.add((DERTaggedObject) seq.getObjectAt(i));
        }
    }

    public void addDataObject(int tagno, byte[] data) {
        this.objects.add(new DERTaggedObject(false, tagno, new DEROctetString(data)));
    }

    public byte[] getDataObject(int tagno) {
        for (DERTaggedObject item : this.objects) {
            if (item.getTagNo() == tagno) {
                return ((DEROctetString) item.getObjectParser(4, false)).getOctets();
            }
        }
        return null;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector asn1vec = new ASN1EncodableVector();
        for (DERTaggedObject item : this.objects) {
            asn1vec.add(item);
        }
        return new DERApplicationSpecific(28, asn1vec);
    }
}

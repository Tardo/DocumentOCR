package org.spongycastle.asn1.icao;

import java.util.Enumeration;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERSequence;

public class DataGroupHash extends ASN1Encodable {
    ASN1OctetString dataGroupHashValue;
    DERInteger dataGroupNumber;

    public static DataGroupHash getInstance(Object obj) {
        if (obj instanceof DataGroupHash) {
            return (DataGroupHash) obj;
        }
        if (obj != null) {
            return new DataGroupHash(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private DataGroupHash(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.dataGroupNumber = DERInteger.getInstance(e.nextElement());
        this.dataGroupHashValue = ASN1OctetString.getInstance(e.nextElement());
    }

    public DataGroupHash(int dataGroupNumber, ASN1OctetString dataGroupHashValue) {
        this.dataGroupNumber = new DERInteger(dataGroupNumber);
        this.dataGroupHashValue = dataGroupHashValue;
    }

    public int getDataGroupNumber() {
        return this.dataGroupNumber.getValue().intValue();
    }

    public ASN1OctetString getDataGroupHashValue() {
        return this.dataGroupHashValue;
    }

    public DERObject toASN1Object() {
        ASN1EncodableVector seq = new ASN1EncodableVector();
        seq.add(this.dataGroupNumber);
        seq.add(this.dataGroupHashValue);
        return new DERSequence(seq);
    }
}

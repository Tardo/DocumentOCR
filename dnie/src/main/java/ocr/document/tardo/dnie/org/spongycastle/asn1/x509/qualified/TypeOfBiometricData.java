package org.spongycastle.asn1.x509.qualified;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;

public class TypeOfBiometricData extends ASN1Encodable implements ASN1Choice {
    public static final int HANDWRITTEN_SIGNATURE = 1;
    public static final int PICTURE = 0;
    DEREncodable obj;

    public static TypeOfBiometricData getInstance(Object obj) {
        if (obj == null || (obj instanceof TypeOfBiometricData)) {
            return (TypeOfBiometricData) obj;
        }
        if (obj instanceof DERInteger) {
            return new TypeOfBiometricData(DERInteger.getInstance(obj).getValue().intValue());
        }
        if (obj instanceof DERObjectIdentifier) {
            return new TypeOfBiometricData(DERObjectIdentifier.getInstance(obj));
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public TypeOfBiometricData(int predefinedBiometricType) {
        if (predefinedBiometricType == 0 || predefinedBiometricType == 1) {
            this.obj = new DERInteger(predefinedBiometricType);
            return;
        }
        throw new IllegalArgumentException("unknow PredefinedBiometricType : " + predefinedBiometricType);
    }

    public TypeOfBiometricData(DERObjectIdentifier BiometricDataID) {
        this.obj = BiometricDataID;
    }

    public boolean isPredefined() {
        return this.obj instanceof DERInteger;
    }

    public int getPredefinedBiometricType() {
        return ((DERInteger) this.obj).getValue().intValue();
    }

    public DERObjectIdentifier getBiometricDataOid() {
        return (DERObjectIdentifier) this.obj;
    }

    public DERObject toASN1Object() {
        return this.obj.getDERObject();
    }
}

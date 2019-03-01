package org.spongycastle.asn1.crmf;

import org.spongycastle.asn1.ASN1Choice;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DERBoolean;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERTaggedObject;

public class PKIArchiveOptions extends ASN1Encodable implements ASN1Choice {
    public static final int archiveRemGenPrivKey = 2;
    public static final int encryptedPrivKey = 0;
    public static final int keyGenParameters = 1;
    private ASN1Encodable value;

    public static PKIArchiveOptions getInstance(Object o) {
        if (o instanceof PKIArchiveOptions) {
            return (PKIArchiveOptions) o;
        }
        if (o instanceof ASN1TaggedObject) {
            return new PKIArchiveOptions((ASN1TaggedObject) o);
        }
        throw new IllegalArgumentException("unknown object: " + o);
    }

    private PKIArchiveOptions(ASN1TaggedObject tagged) {
        switch (tagged.getTagNo()) {
            case 0:
                this.value = EncryptedKey.getInstance(tagged.getObject());
                return;
            case 1:
                this.value = ASN1OctetString.getInstance(tagged, false);
                return;
            case 2:
                this.value = DERBoolean.getInstance(tagged, false);
                return;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tagged.getTagNo());
        }
    }

    public PKIArchiveOptions(EncryptedKey encKey) {
        this.value = encKey;
    }

    public PKIArchiveOptions(ASN1OctetString keyGenParameters) {
        this.value = keyGenParameters;
    }

    public PKIArchiveOptions(boolean archiveRemGenPrivKey) {
        this.value = new DERBoolean(archiveRemGenPrivKey);
    }

    public int getType() {
        if (this.value instanceof EncryptedKey) {
            return 0;
        }
        if (this.value instanceof ASN1OctetString) {
            return 1;
        }
        return 2;
    }

    public ASN1Encodable getValue() {
        return this.value;
    }

    public DERObject toASN1Object() {
        if (this.value instanceof EncryptedKey) {
            return new DERTaggedObject(true, 0, this.value);
        }
        if (this.value instanceof ASN1OctetString) {
            return new DERTaggedObject(false, 1, this.value);
        }
        return new DERTaggedObject(false, 2, this.value);
    }
}

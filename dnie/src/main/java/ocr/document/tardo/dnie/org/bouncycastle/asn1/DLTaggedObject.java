package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.crypto.tls.CipherSuite;

public class DLTaggedObject extends ASN1TaggedObject {
    private static final byte[] ZERO_BYTES = new byte[0];

    public DLTaggedObject(boolean z, int i, ASN1Encodable aSN1Encodable) {
        super(z, i, aSN1Encodable);
    }

    void encode(ASN1OutputStream aSN1OutputStream) throws IOException {
        int i = CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
        if (this.empty) {
            aSN1OutputStream.writeEncoded(CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, this.tagNo, ZERO_BYTES);
            return;
        }
        ASN1Primitive toDLObject = this.obj.toASN1Primitive().toDLObject();
        if (this.explicit) {
            aSN1OutputStream.writeTag(CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, this.tagNo);
            aSN1OutputStream.writeLength(toDLObject.encodedLength());
            aSN1OutputStream.writeObject(toDLObject);
            return;
        }
        if (!toDLObject.isConstructed()) {
            i = 128;
        }
        aSN1OutputStream.writeTag(i, this.tagNo);
        aSN1OutputStream.writeImplicitObject(toDLObject);
    }

    int encodedLength() throws IOException {
        if (this.empty) {
            return StreamUtil.calculateTagLength(this.tagNo) + 1;
        }
        int encodedLength = this.obj.toASN1Primitive().toDLObject().encodedLength();
        return this.explicit ? encodedLength + (StreamUtil.calculateTagLength(this.tagNo) + StreamUtil.calculateBodyLength(encodedLength)) : (encodedLength - 1) + StreamUtil.calculateTagLength(this.tagNo);
    }

    boolean isConstructed() {
        return (this.empty || this.explicit) ? true : this.obj.toASN1Primitive().toDLObject().isConstructed();
    }
}

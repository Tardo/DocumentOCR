package org.spongycastle.asn1;

import java.io.IOException;
import org.bouncycastle.crypto.tls.CipherSuite;

public class DERTaggedObject extends ASN1TaggedObject {
    private static final byte[] ZERO_BYTES = new byte[0];

    public DERTaggedObject(int tagNo, DEREncodable obj) {
        super(tagNo, obj);
    }

    public DERTaggedObject(boolean explicit, int tagNo, DEREncodable obj) {
        super(explicit, tagNo, obj);
    }

    public DERTaggedObject(int tagNo) {
        super(false, tagNo, new DERSequence());
    }

    void encode(DEROutputStream out) throws IOException {
        if (this.empty) {
            out.writeEncoded(CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, this.tagNo, ZERO_BYTES);
            return;
        }
        byte[] bytes = this.obj.getDERObject().getEncoded("DER");
        if (this.explicit) {
            out.writeEncoded(CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, this.tagNo, bytes);
            return;
        }
        int flags;
        if ((bytes[0] & 32) != 0) {
            flags = CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
        } else {
            flags = 128;
        }
        out.writeTag(flags, this.tagNo);
        out.write(bytes, 1, bytes.length - 1);
    }
}

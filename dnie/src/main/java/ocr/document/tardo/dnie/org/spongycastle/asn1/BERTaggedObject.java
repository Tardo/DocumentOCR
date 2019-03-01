package org.spongycastle.asn1;

import java.io.IOException;
import java.util.Enumeration;
import org.bouncycastle.crypto.tls.CipherSuite;

public class BERTaggedObject extends DERTaggedObject {
    public BERTaggedObject(int tagNo, DEREncodable obj) {
        super(tagNo, obj);
    }

    public BERTaggedObject(boolean explicit, int tagNo, DEREncodable obj) {
        super(explicit, tagNo, obj);
    }

    public BERTaggedObject(int tagNo) {
        super(false, tagNo, new BERSequence());
    }

    void encode(DEROutputStream out) throws IOException {
        if ((out instanceof ASN1OutputStream) || (out instanceof BEROutputStream)) {
            out.writeTag(CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256, this.tagNo);
            out.write(128);
            if (!this.empty) {
                if (this.explicit) {
                    out.writeObject(this.obj);
                } else {
                    Enumeration e;
                    if (this.obj instanceof ASN1OctetString) {
                        if (this.obj instanceof BERConstructedOctetString) {
                            e = ((BERConstructedOctetString) this.obj).getObjects();
                        } else {
                            e = new BERConstructedOctetString(this.obj.getOctets()).getObjects();
                        }
                    } else if (this.obj instanceof ASN1Sequence) {
                        e = ((ASN1Sequence) this.obj).getObjects();
                    } else if (this.obj instanceof ASN1Set) {
                        e = ((ASN1Set) this.obj).getObjects();
                    } else {
                        throw new RuntimeException("not implemented: " + this.obj.getClass().getName());
                    }
                    while (e.hasMoreElements()) {
                        out.writeObject(e.nextElement());
                    }
                }
            }
            out.write(0);
            out.write(0);
            return;
        }
        super.encode(out);
    }
}

package custom.org.apache.harmony.security.provider.crypto;

import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;

class ThreeIntegerSequence {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), ASN1Integer.getInstance(), ASN1Integer.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new ThreeIntegerSequence((byte[]) values[0], (byte[]) values[1], (byte[]) values[2]);
        }

        protected void getValues(Object object, Object[] values) {
            ThreeIntegerSequence mySeq = (ThreeIntegerSequence) object;
            values[0] = mySeq.f14p;
            values[1] = mySeq.f15q;
            values[2] = mySeq.f13g;
        }
    };
    private byte[] encoding = null;
    /* renamed from: g */
    byte[] f13g;
    /* renamed from: p */
    byte[] f14p;
    /* renamed from: q */
    byte[] f15q;

    ThreeIntegerSequence(byte[] p, byte[] q, byte[] g) {
        this.f14p = p;
        this.f15q = q;
        this.f13g = g;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}

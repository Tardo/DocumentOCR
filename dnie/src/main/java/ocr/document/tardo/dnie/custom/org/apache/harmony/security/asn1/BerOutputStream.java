package custom.org.apache.harmony.security.asn1;

import org.bouncycastle.asn1.eac.CertificateBody;

public class BerOutputStream {
    public Object content;
    public byte[] encoded;
    public int length;
    protected int offset;

    public final void encodeTag(int tag) {
        byte[] bArr = this.encoded;
        int i = this.offset;
        this.offset = i + 1;
        bArr[i] = (byte) tag;
        if (this.length > CertificateBody.profileType) {
            int eLen;
            byte numOctets = (byte) 1;
            for (eLen = this.length >> 8; eLen > 0; eLen >>= 8) {
                numOctets = (byte) (numOctets + 1);
            }
            this.encoded[this.offset] = (byte) (numOctets | 128);
            this.offset++;
            eLen = this.length;
            int numOffset = (this.offset + numOctets) - 1;
            byte i2 = (byte) 0;
            while (i2 < numOctets) {
                this.encoded[numOffset - i2] = (byte) eLen;
                i2++;
                eLen >>= 8;
            }
            this.offset += numOctets;
            return;
        }
        bArr = this.encoded;
        i = this.offset;
        this.offset = i + 1;
        bArr[i] = (byte) this.length;
    }

    public void encodeANY() {
        System.arraycopy(this.content, 0, this.encoded, this.offset, this.length);
        this.offset += this.length;
    }

    public void encodeBitString() {
        BitString bStr = this.content;
        this.encoded[this.offset] = (byte) bStr.unusedBits;
        System.arraycopy(bStr.bytes, 0, this.encoded, this.offset + 1, this.length - 1);
        this.offset += this.length;
    }

    public void encodeBoolean() {
        if (((Boolean) this.content).booleanValue()) {
            this.encoded[this.offset] = (byte) -1;
        } else {
            this.encoded[this.offset] = (byte) 0;
        }
        this.offset++;
    }

    public void encodeChoice(ASN1Choice choice) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void encodeExplicit(ASN1Explicit explicit) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void encodeGeneralizedTime() {
        System.arraycopy(this.content, 0, this.encoded, this.offset, this.length);
        this.offset += this.length;
    }

    public void encodeUTCTime() {
        System.arraycopy(this.content, 0, this.encoded, this.offset, this.length);
        this.offset += this.length;
    }

    public void encodeInteger() {
        System.arraycopy(this.content, 0, this.encoded, this.offset, this.length);
        this.offset += this.length;
    }

    public void encodeOctetString() {
        System.arraycopy(this.content, 0, this.encoded, this.offset, this.length);
        this.offset += this.length;
    }

    public void encodeOID() {
        int elem;
        int[] oid = (int[]) this.content;
        int oidLen = this.length;
        int i = oid.length - 1;
        while (i > 1) {
            elem = oid[i];
            if (elem > CertificateBody.profileType) {
                this.encoded[(this.offset + oidLen) - 1] = (byte) (elem & CertificateBody.profileType);
                for (elem >>= 7; elem > 0; elem >>= 7) {
                    oidLen--;
                    this.encoded[(this.offset + oidLen) - 1] = (byte) (elem | 128);
                }
            } else {
                this.encoded[(this.offset + oidLen) - 1] = (byte) elem;
            }
            i--;
            oidLen--;
        }
        elem = (oid[0] * 40) + oid[1];
        if (elem > CertificateBody.profileType) {
            this.encoded[(this.offset + oidLen) - 1] = (byte) (elem & CertificateBody.profileType);
            for (elem >>= 7; elem > 0; elem >>= 7) {
                oidLen--;
                this.encoded[(this.offset + oidLen) - 1] = (byte) (elem | 128);
            }
        } else {
            this.encoded[(this.offset + oidLen) - 1] = (byte) elem;
        }
        this.offset += this.length;
    }

    public void encodeSequence(ASN1Sequence sequence) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void encodeSequenceOf(ASN1SequenceOf sequenceOf) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void encodeSet(ASN1Set set) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void encodeSetOf(ASN1SetOf setOf) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void encodeString() {
        System.arraycopy(this.content, 0, this.encoded, this.offset, this.length);
        this.offset += this.length;
    }

    public void getChoiceLength(ASN1Choice choice) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void getExplicitLength(ASN1Explicit sequence) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void getSequenceLength(ASN1Sequence sequence) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void getSequenceOfLength(ASN1SequenceOf sequence) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void getSetLength(ASN1Set set) {
        throw new RuntimeException("Is not implemented yet");
    }

    public void getSetOfLength(ASN1SetOf setOf) {
        throw new RuntimeException("Is not implemented yet");
    }

    public int getStringLength(Object object) {
        throw new RuntimeException("Is not implemented yet");
    }
}

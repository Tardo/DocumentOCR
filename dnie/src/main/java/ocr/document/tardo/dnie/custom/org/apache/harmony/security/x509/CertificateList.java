package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1BitString;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BitString;
import custom.org.apache.harmony.security.utils.Array;

public class CertificateList {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{TBSCertList.ASN1, AlgorithmIdentifier.ASN1, ASN1BitString.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new CertificateList((TBSCertList) values[0], (AlgorithmIdentifier) values[1], ((BitString) values[2]).bytes, in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            CertificateList certlist = (CertificateList) object;
            values[0] = certlist.tbsCertList;
            values[1] = certlist.signatureAlgorithm;
            values[2] = new BitString(certlist.signatureValue, 0);
        }
    };
    private byte[] encoding;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final byte[] signatureValue;
    private final TBSCertList tbsCertList;

    public CertificateList(TBSCertList tbsCertList, AlgorithmIdentifier signatureAlgorithm, byte[] signatureValue) {
        this.tbsCertList = tbsCertList;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureValue = new byte[signatureValue.length];
        System.arraycopy(signatureValue, 0, this.signatureValue, 0, signatureValue.length);
    }

    private CertificateList(TBSCertList tbsCertList, AlgorithmIdentifier signatureAlgorithm, byte[] signatureValue, byte[] encoding) {
        this(tbsCertList, signatureAlgorithm, signatureValue);
        this.encoding = encoding;
    }

    public TBSCertList getTbsCertList() {
        return this.tbsCertList;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public byte[] getSignatureValue() {
        byte[] result = new byte[this.signatureValue.length];
        System.arraycopy(this.signatureValue, 0, result, 0, this.signatureValue.length);
        return result;
    }

    public String toString() {
        StringBuffer res = new StringBuffer();
        this.tbsCertList.dumpValue(res);
        res.append("\nSignature Value:\n");
        res.append(Array.toString(this.signatureValue, ""));
        return res.toString();
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }
}

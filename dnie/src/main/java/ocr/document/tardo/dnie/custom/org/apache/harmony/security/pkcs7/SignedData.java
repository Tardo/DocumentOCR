package custom.org.apache.harmony.security.pkcs7;

import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SetOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x509.AlgorithmIdentifier;
import custom.org.apache.harmony.security.x509.Certificate;
import custom.org.apache.harmony.security.x509.CertificateList;
import java.util.List;

public class SignedData {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), new ASN1SetOf(AlgorithmIdentifier.ASN1), ContentInfo.ASN1, new ASN1Implicit(0, new ASN1SetOf(Certificate.ASN1)), new ASN1Implicit(1, new ASN1SetOf(CertificateList.ASN1)), new ASN1SetOf(SignerInfo.ASN1)}) {
        protected void getValues(Object object, Object[] values) {
            SignedData sd = (SignedData) object;
            values[0] = new byte[]{(byte) sd.version};
            values[1] = sd.digestAlgorithms;
            values[2] = sd.contentInfo;
            values[3] = sd.certificates;
            values[4] = sd.crls;
            values[5] = sd.signerInfos;
        }

        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new SignedData(ASN1Integer.toIntValue(values[0]), (List) values[1], (ContentInfo) values[2], (List) values[3], (List) values[4], (List) values[5]);
        }
    };
    private List certificates;
    private ContentInfo contentInfo;
    private List crls;
    private List digestAlgorithms;
    private List signerInfos;
    private int version;

    public SignedData(int version, List digestAlgorithms, ContentInfo contentInfo, List certificates, List crls, List signerInfos) {
        this.version = version;
        this.digestAlgorithms = digestAlgorithms;
        this.contentInfo = contentInfo;
        this.certificates = certificates;
        this.crls = crls;
        this.signerInfos = signerInfos;
    }

    public List getCertificates() {
        return this.certificates;
    }

    public List getCRLs() {
        return this.crls;
    }

    public List getSignerInfos() {
        return this.signerInfos;
    }

    public ContentInfo getContentInfo() {
        return this.contentInfo;
    }

    public List getDigestAlgorithms() {
        return this.digestAlgorithms;
    }

    public int getVersion() {
        return this.version;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("---- SignedData:");
        res.append("\nversion: ");
        res.append(this.version);
        res.append("\ndigestAlgorithms: ");
        res.append(this.digestAlgorithms.toString());
        res.append("\ncontentInfo: ");
        res.append(this.contentInfo.toString());
        res.append("\ncertificates: ");
        if (this.certificates != null) {
            res.append(this.certificates.toString());
        }
        res.append("\ncrls: ");
        if (this.crls != null) {
            res.append(this.crls.toString());
        }
        res.append("\nsignerInfos:\n");
        res.append(this.signerInfos.toString());
        res.append("\n---- SignedData End\n]");
        return res.toString();
    }
}

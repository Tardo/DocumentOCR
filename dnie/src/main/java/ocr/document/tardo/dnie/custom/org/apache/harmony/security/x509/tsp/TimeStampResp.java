package custom.org.apache.harmony.security.x509.tsp;

import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.pkcs7.ContentInfo;

public class TimeStampResp {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{PKIStatusInfo.ASN1, ContentInfo.ASN1}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new TimeStampResp((PKIStatusInfo) values[0], (ContentInfo) values[1]);
        }

        protected void getValues(Object object, Object[] values) {
            TimeStampResp resp = (TimeStampResp) object;
            values[0] = resp.status;
            values[1] = resp.timeStampToken;
        }
    };
    private final PKIStatusInfo status;
    private final ContentInfo timeStampToken;

    public TimeStampResp(PKIStatusInfo status, ContentInfo timeStampToken) {
        this.status = status;
        this.timeStampToken = timeStampToken;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("-- TimeStampResp:");
        res.append("\nstatus:  ");
        res.append(this.status);
        res.append("\ntimeStampToken:  ");
        res.append(this.timeStampToken);
        res.append("\n-- TimeStampResp End\n");
        return res.toString();
    }

    public PKIStatusInfo getStatus() {
        return this.status;
    }

    public ContentInfo getTimeStampToken() {
        return this.timeStampToken;
    }
}

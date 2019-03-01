package custom.org.apache.harmony.security.x509.tsp;

import custom.org.apache.harmony.security.asn1.ASN1BitString;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1StringType;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.BitString;
import java.math.BigInteger;
import java.util.List;

public class PKIStatusInfo {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), new ASN1SequenceOf(ASN1StringType.UTF8STRING), ASN1BitString.getInstance()}) {
        protected void getValues(Object object, Object[] values) {
            PKIStatusInfo psi = (PKIStatusInfo) object;
            values[0] = BigInteger.valueOf((long) psi.status.getStatus()).toByteArray();
            values[1] = psi.statusString;
            if (psi.failInfo != null) {
                boolean[] failInfoBoolArray = new boolean[PKIFailureInfo.getMaxValue()];
                failInfoBoolArray[psi.failInfo.getValue()] = true;
                values[2] = new BitString(failInfoBoolArray);
                return;
            }
            values[2] = null;
        }

        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            int failInfoValue = -1;
            if (values[2] != null) {
                boolean[] failInfoBoolArray = ((BitString) values[2]).toBooleanArray();
                for (int i = 0; i < failInfoBoolArray.length; i++) {
                    if (failInfoBoolArray[i]) {
                        failInfoValue = i;
                        break;
                    }
                }
            }
            return new PKIStatusInfo(PKIStatus.getInstance(ASN1Integer.toIntValue(values[0])), (List) values[1], PKIFailureInfo.getInstance(failInfoValue));
        }
    };
    private final PKIFailureInfo failInfo;
    private final PKIStatus status;
    private final List statusString;

    public PKIStatusInfo(PKIStatus pKIStatus, List statusString, PKIFailureInfo failInfo) {
        this.status = pKIStatus;
        this.statusString = statusString;
        this.failInfo = failInfo;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("-- PKIStatusInfo:");
        res.append("\nPKIStatus : ");
        res.append(this.status);
        res.append("\nstatusString:  ");
        res.append(this.statusString);
        res.append("\nfailInfo:  ");
        res.append(this.failInfo);
        res.append("\n-- PKIStatusInfo End\n");
        return res.toString();
    }

    public PKIFailureInfo getFailInfo() {
        return this.failInfo;
    }

    public PKIStatus getStatus() {
        return this.status;
    }

    public List getStatusString() {
        return this.statusString;
    }
}

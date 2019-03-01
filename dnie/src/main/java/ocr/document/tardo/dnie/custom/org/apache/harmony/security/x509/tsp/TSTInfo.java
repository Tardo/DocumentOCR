package custom.org.apache.harmony.security.x509.tsp;

import custom.org.apache.harmony.security.asn1.ASN1Boolean;
import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1GeneralizedTime;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.x509.Extensions;
import custom.org.apache.harmony.security.x509.GeneralName;
import java.math.BigInteger;
import java.util.Date;

public class TSTInfo {
    public static final ASN1Sequence ACCURACY = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), ASN1Integer.getInstance(), ASN1Integer.getInstance()}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            int[] accuracy = new int[3];
            int i = 0;
            while (i < 3) {
                if (values[i] != null) {
                    accuracy[i] = ASN1Integer.toIntValue(values[i]);
                    if (i > 0 && (accuracy[i] < 0 || accuracy[i] > 999)) {
                        throw new RuntimeException(Messages.getString("security.1A3", accuracy[i]));
                    }
                }
                i++;
            }
            return accuracy;
        }

        protected void getValues(Object object, Object[] values) {
            int[] accuracy = (int[]) object;
            int i = 0;
            while (i < 3) {
                if (i <= 0 || (accuracy[i] >= 0 && accuracy[i] <= 999)) {
                    values[i] = BigInteger.valueOf((long) accuracy[i]).toByteArray();
                    i++;
                } else {
                    throw new RuntimeException(Messages.getString("security.1A3", accuracy[i]));
                }
            }
        }
    };
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), ASN1Oid.getInstance(), MessageImprint.ASN1, ASN1Integer.getInstance(), ASN1GeneralizedTime.getInstance(), ACCURACY, ASN1Boolean.getInstance(), ASN1Integer.getInstance(), new ASN1Explicit(0, GeneralName.ASN1), new ASN1Implicit(1, Extensions.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) {
            Object[] values = (Object[]) in.content;
            return new TSTInfo(ASN1Integer.toIntValue(values[0]), ObjectIdentifier.toString((int[]) values[1]), (MessageImprint) values[2], new BigInteger((byte[]) values[3]), (Date) values[4], (int[]) values[5], (Boolean) values[6], values[7] == null ? null : new BigInteger((byte[]) values[7]), (GeneralName) values[8], (Extensions) values[9]);
        }

        protected void getValues(Object object, Object[] values) {
            TSTInfo info = (TSTInfo) object;
            values[0] = ASN1Integer.fromIntValue(info.version);
            values[1] = ObjectIdentifier.toIntArray(info.policy);
            values[2] = info.messageImprint;
            values[3] = info.serialNumber.toByteArray();
            values[4] = info.genTime;
            values[5] = info.accuracy;
            values[6] = info.ordering;
            values[7] = info.nonce == null ? null : info.nonce.toByteArray();
            values[8] = info.tsa;
            values[9] = info.extensions;
        }
    };
    private final int[] accuracy;
    private final Extensions extensions;
    private final Date genTime;
    private final MessageImprint messageImprint;
    private final BigInteger nonce;
    private final Boolean ordering;
    private final String policy;
    private final BigInteger serialNumber;
    private final GeneralName tsa;
    private final int version;

    public TSTInfo(int version, String policy, MessageImprint messageImprint, BigInteger serialNumber, Date genTime, int[] accuracy, Boolean ordering, BigInteger nonce, GeneralName tsa, Extensions extensions) {
        this.version = version;
        this.policy = policy;
        this.messageImprint = messageImprint;
        this.serialNumber = serialNumber;
        this.genTime = genTime;
        this.accuracy = accuracy;
        this.ordering = ordering;
        this.nonce = nonce;
        this.tsa = tsa;
        this.extensions = extensions;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("-- TSTInfo:");
        res.append("\nversion:  ");
        res.append(this.version);
        res.append("\npolicy:  ");
        res.append(this.policy);
        res.append("\nmessageImprint:  ");
        res.append(this.messageImprint);
        res.append("\nserialNumber:  ");
        res.append(this.serialNumber);
        res.append("\ngenTime:  ");
        res.append(this.genTime);
        res.append("\naccuracy:  ");
        if (this.accuracy != null) {
            res.append(this.accuracy[0] + " sec, " + this.accuracy[1] + " millis, " + this.accuracy[2] + " micros");
        }
        res.append("\nordering:  ");
        res.append(this.ordering);
        res.append("\nnonce:  ");
        res.append(this.nonce);
        res.append("\ntsa:  ");
        res.append(this.tsa);
        res.append("\nextensions:  ");
        res.append(this.extensions);
        res.append("\n-- TSTInfo End\n");
        return res.toString();
    }

    public int[] getAccuracy() {
        return this.accuracy;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public Date getGenTime() {
        return this.genTime;
    }

    public MessageImprint getMessageImprint() {
        return this.messageImprint;
    }

    public BigInteger getNonce() {
        return this.nonce;
    }

    public Boolean getOrdering() {
        return this.ordering;
    }

    public String getPolicy() {
        return this.policy;
    }

    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    public GeneralName getTsa() {
        return this.tsa;
    }

    public int getVersion() {
        return this.version;
    }
}

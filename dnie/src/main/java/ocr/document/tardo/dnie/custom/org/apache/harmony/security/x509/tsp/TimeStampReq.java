package custom.org.apache.harmony.security.x509.tsp;

import custom.org.apache.harmony.security.asn1.ASN1Boolean;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import custom.org.apache.harmony.security.x509.Extensions;
import java.math.BigInteger;

public class TimeStampReq {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), MessageImprint.ASN1, ASN1Oid.getInstance(), ASN1Integer.getInstance(), ASN1Boolean.getInstance(), new ASN1Implicit(0, Extensions.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) {
            BigInteger nonce;
            Object[] values = (Object[]) in.content;
            String objID = values[2] == null ? null : ObjectIdentifier.toString((int[]) values[2]);
            if (values[3] == null) {
                nonce = null;
            } else {
                nonce = new BigInteger((byte[]) values[3]);
            }
            if (values[5] == null) {
                return new TimeStampReq(ASN1Integer.toIntValue(values[0]), (MessageImprint) values[1], objID, nonce, (Boolean) values[4], null, in.getEncoded());
            }
            return new TimeStampReq(ASN1Integer.toIntValue(values[0]), (MessageImprint) values[1], objID, nonce, (Boolean) values[4], (Extensions) values[5], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            byte[] bArr = null;
            TimeStampReq req = (TimeStampReq) object;
            values[0] = ASN1Integer.fromIntValue(req.version);
            values[1] = req.messageImprint;
            values[2] = req.reqPolicy == null ? null : ObjectIdentifier.toIntArray(req.reqPolicy);
            if (req.nonce != null) {
                bArr = req.nonce.toByteArray();
            }
            values[3] = bArr;
            values[4] = req.certReq == null ? Boolean.FALSE : req.certReq;
            values[5] = req.extensions;
        }
    };
    private final Boolean certReq;
    private byte[] encoding;
    private final Extensions extensions;
    private final MessageImprint messageImprint;
    private final BigInteger nonce;
    private final String reqPolicy;
    private final int version;

    public TimeStampReq(int version, MessageImprint messageImprint, String reqPolicy, BigInteger nonce, Boolean certReq, Extensions extensions) {
        this.version = version;
        this.messageImprint = messageImprint;
        this.reqPolicy = reqPolicy;
        this.nonce = nonce;
        this.certReq = certReq;
        this.extensions = extensions;
    }

    private TimeStampReq(int version, MessageImprint messageImprint, String reqPolicy, BigInteger nonce, Boolean certReq, Extensions extensions, byte[] encoding) {
        this(version, messageImprint, reqPolicy, nonce, certReq, extensions);
        this.encoding = encoding;
    }

    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append("-- TimeStampReq:");
        res.append("\nversion : ");
        res.append(this.version);
        res.append("\nmessageImprint:  ");
        res.append(this.messageImprint);
        res.append("\nreqPolicy:  ");
        res.append(this.reqPolicy);
        res.append("\nnonce:  ");
        res.append(this.nonce);
        res.append("\ncertReq:  ");
        res.append(this.certReq);
        res.append("\nextensions:  ");
        res.append(this.extensions);
        res.append("\n-- TimeStampReq End\n");
        return res.toString();
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public Boolean getCertReq() {
        return this.certReq;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public MessageImprint getMessageImprint() {
        return this.messageImprint;
    }

    public BigInteger getNonce() {
        return this.nonce;
    }

    public String getReqPolicy() {
        return this.reqPolicy;
    }

    public int getVersion() {
        return this.version;
    }
}

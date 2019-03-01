package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.x501.Name;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;

public class TBSCertList {
    public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), AlgorithmIdentifier.ASN1, Name.ASN1, Time.ASN1, Time.ASN1, new ASN1SequenceOf(RevokedCertificate.ASN1), new ASN1Explicit(0, Extensions.ASN1)}) {
        protected Object getDecodedObject(BerInputStream in) throws IOException {
            Object[] values = (Object[]) in.content;
            return new TBSCertList(values[0] == null ? 1 : ASN1Integer.toIntValue(values[0]) + 1, (AlgorithmIdentifier) values[1], (Name) values[2], (Date) values[3], (Date) values[4], (List) values[5], (Extensions) values[6], in.getEncoded());
        }

        protected void getValues(Object object, Object[] values) {
            TBSCertList tbs = (TBSCertList) object;
            values[0] = tbs.version > 1 ? ASN1Integer.fromIntValue(tbs.version - 1) : null;
            values[1] = tbs.signature;
            values[2] = tbs.issuer;
            values[3] = tbs.thisUpdate;
            values[4] = tbs.nextUpdate;
            values[5] = tbs.revokedCertificates;
            values[6] = tbs.crlExtensions;
        }
    };
    private final Extensions crlExtensions;
    private byte[] encoding;
    private final Name issuer;
    private final Date nextUpdate;
    private final List revokedCertificates;
    private final AlgorithmIdentifier signature;
    private final Date thisUpdate;
    private final int version;

    public static class RevokedCertificate {
        public static final ASN1Sequence ASN1 = new ASN1Sequence(new ASN1Type[]{ASN1Integer.getInstance(), Time.ASN1, Extensions.ASN1}) {
            protected Object getDecodedObject(BerInputStream in) {
                Object[] values = (Object[]) in.content;
                return new RevokedCertificate(new BigInteger((byte[]) values[0]), (Date) values[1], (Extensions) values[2]);
            }

            protected void getValues(Object object, Object[] values) {
                RevokedCertificate rcert = (RevokedCertificate) object;
                values[0] = rcert.userCertificate.toByteArray();
                values[1] = rcert.revocationDate;
                values[2] = rcert.crlEntryExtensions;
            }
        };
        private final Extensions crlEntryExtensions;
        private byte[] encoding;
        private X500Principal issuer;
        private boolean issuerRetrieved;
        private final Date revocationDate;
        private final BigInteger userCertificate;

        public RevokedCertificate(BigInteger userCertificate, Date revocationDate, Extensions crlEntryExtensions) {
            this.userCertificate = userCertificate;
            this.revocationDate = revocationDate;
            this.crlEntryExtensions = crlEntryExtensions;
        }

        public Extensions getCrlEntryExtensions() {
            return this.crlEntryExtensions;
        }

        public BigInteger getUserCertificate() {
            return this.userCertificate;
        }

        public Date getRevocationDate() {
            return this.revocationDate;
        }

        public X500Principal getIssuer() {
            if (this.crlEntryExtensions == null) {
                return null;
            }
            if (!this.issuerRetrieved) {
                try {
                    this.issuer = this.crlEntryExtensions.valueOfCertificateIssuerExtension();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                this.issuerRetrieved = true;
            }
            return this.issuer;
        }

        public byte[] getEncoded() {
            if (this.encoding == null) {
                this.encoding = ASN1.encode(this);
            }
            return this.encoding;
        }

        public boolean equals(Object rc) {
            if (!(rc instanceof RevokedCertificate)) {
                return false;
            }
            RevokedCertificate rcert = (RevokedCertificate) rc;
            if (!this.userCertificate.equals(rcert.userCertificate) || this.revocationDate.getTime() / 1000 != rcert.revocationDate.getTime() / 1000) {
                return false;
            }
            if (this.crlEntryExtensions == null) {
                if (rcert.crlEntryExtensions != null) {
                    return false;
                }
            } else if (!this.crlEntryExtensions.equals(rcert.crlEntryExtensions)) {
                return false;
            }
            return true;
        }

        public int hashCode() {
            return (this.crlEntryExtensions == null ? 0 : this.crlEntryExtensions.hashCode()) + ((((int) this.revocationDate.getTime()) / 1000) + (this.userCertificate.hashCode() * 37));
        }

        public void dumpValue(StringBuffer buffer, String prefix) {
            buffer.append(prefix).append("Certificate Serial Number: ").append(this.userCertificate).append('\n');
            buffer.append(prefix).append("Revocation Date: ").append(this.revocationDate);
            if (this.crlEntryExtensions != null) {
                buffer.append('\n').append(prefix).append("CRL Entry Extensions: [");
                this.crlEntryExtensions.dumpValue(buffer, prefix + "  ");
                buffer.append(prefix).append(']');
            }
        }
    }

    public TBSCertList(AlgorithmIdentifier signature, Name issuer, Date thisUpdate) {
        this.version = 1;
        this.signature = signature;
        this.issuer = issuer;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = null;
        this.revokedCertificates = null;
        this.crlExtensions = null;
    }

    public TBSCertList(int version, AlgorithmIdentifier signature, Name issuer, Date thisUpdate, Date nextUpdate, List revokedCertificates, Extensions crlExtensions) {
        this.version = version;
        this.signature = signature;
        this.issuer = issuer;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.revokedCertificates = revokedCertificates;
        this.crlExtensions = crlExtensions;
    }

    private TBSCertList(int version, AlgorithmIdentifier signature, Name issuer, Date thisUpdate, Date nextUpdate, List revokedCertificates, Extensions crlExtensions, byte[] encoding) {
        this.version = version;
        this.signature = signature;
        this.issuer = issuer;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.revokedCertificates = revokedCertificates;
        this.crlExtensions = crlExtensions;
        this.encoding = encoding;
    }

    public int getVersion() {
        return this.version;
    }

    public AlgorithmIdentifier getSignature() {
        return this.signature;
    }

    public Name getIssuer() {
        return this.issuer;
    }

    public Date getThisUpdate() {
        return this.thisUpdate;
    }

    public Date getNextUpdate() {
        return this.nextUpdate;
    }

    public List getRevokedCertificates() {
        return this.revokedCertificates;
    }

    public Extensions getCrlExtensions() {
        return this.crlExtensions;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(this);
        }
        return this.encoding;
    }

    public boolean equals(Object tbs) {
        if (!(tbs instanceof TBSCertList)) {
            return false;
        }
        TBSCertList tbscert = (TBSCertList) tbs;
        if (this.version != tbscert.version || !this.signature.equals(tbscert.signature) || !Arrays.equals(this.issuer.getEncoded(), tbscert.issuer.getEncoded()) || this.thisUpdate.getTime() / 1000 != tbscert.thisUpdate.getTime() / 1000) {
            return false;
        }
        if (this.nextUpdate == null) {
            if (tbscert.nextUpdate != null) {
                return false;
            }
        } else if (this.nextUpdate.getTime() / 1000 != tbscert.nextUpdate.getTime() / 1000) {
            return false;
        }
        if (((this.revokedCertificates != null && tbscert.revokedCertificates != null) || this.revokedCertificates != tbscert.revokedCertificates) && (!this.revokedCertificates.containsAll(tbscert.revokedCertificates) || this.revokedCertificates.size() != tbscert.revokedCertificates.size())) {
            return false;
        }
        if (this.crlExtensions == null) {
            if (tbscert.crlExtensions != null) {
                return false;
            }
        } else if (!this.crlExtensions.equals(tbscert.crlExtensions)) {
            return false;
        }
        return true;
    }

    public int hashCode() {
        return (((((this.version * 37) + this.signature.hashCode()) * 37) + this.issuer.getEncoded().hashCode()) * 37) + (((int) this.thisUpdate.getTime()) / 1000);
    }

    public void dumpValue(StringBuffer buffer) {
        buffer.append("X.509 CRL v").append(this.version);
        buffer.append("\nSignature Algorithm: [");
        this.signature.dumpValue(buffer);
        buffer.append(']');
        buffer.append("\nIssuer: ").append(this.issuer.getName("RFC2253"));
        buffer.append("\n\nThis Update: ").append(this.thisUpdate);
        buffer.append("\nNext Update: ").append(this.nextUpdate).append('\n');
        if (this.revokedCertificates != null) {
            buffer.append("\nRevoked Certificates: ").append(this.revokedCertificates.size()).append(" [");
            int number = 1;
            for (RevokedCertificate dumpValue : this.revokedCertificates) {
                int number2 = number + 1;
                buffer.append("\n  [").append(number).append(']');
                dumpValue.dumpValue(buffer, "  ");
                buffer.append('\n');
                number = number2;
            }
            buffer.append("]\n");
        }
        if (this.crlExtensions != null) {
            buffer.append("\nCRL Extensions: ").append(this.crlExtensions.size()).append(" [");
            this.crlExtensions.dumpValue(buffer, "  ");
            buffer.append("]\n");
        }
    }
}

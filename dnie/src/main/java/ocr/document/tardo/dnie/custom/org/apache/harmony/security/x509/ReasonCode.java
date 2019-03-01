package custom.org.apache.harmony.security.x509;

import custom.org.apache.harmony.security.asn1.ASN1Enumerated;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import java.io.IOException;

public class ReasonCode extends ExtensionValue {
    public static final byte AA_COMPROMISE = (byte) 10;
    public static final byte AFFILIATION_CHANGED = (byte) 3;
    public static final ASN1Type ASN1 = ASN1Enumerated.getInstance();
    public static final byte CA_COMPROMISE = (byte) 2;
    public static final byte CERTIFICATE_HOLD = (byte) 6;
    public static final byte CESSATION_OF_OPERATION = (byte) 5;
    public static final byte KEY_COMPROMISE = (byte) 1;
    public static final byte PRIVILEGE_WITHDRAWN = (byte) 9;
    public static final byte REMOVE_FROM_CRL = (byte) 8;
    public static final byte SUPERSEDED = (byte) 4;
    public static final byte UNSPECIFIED = (byte) 0;
    private final byte code;

    public ReasonCode(byte code) {
        this.code = code;
    }

    public ReasonCode(byte[] encoding) throws IOException {
        super(encoding);
        this.code = ((byte[]) ASN1.decode(encoding))[0];
    }

    public int getCode() {
        return this.code;
    }

    public byte[] getEncoded() {
        if (this.encoding == null) {
            this.encoding = ASN1.encode(new byte[]{this.code});
        }
        return this.encoding;
    }

    public void dumpValue(StringBuffer buffer, String prefix) {
        buffer.append(prefix).append("Reason Code: [ ");
        switch (this.code) {
            case (byte) 0:
                buffer.append("unspecified");
                break;
            case (byte) 1:
                buffer.append("keyCompromise");
                break;
            case (byte) 2:
                buffer.append("cACompromise");
                break;
            case (byte) 3:
                buffer.append("affiliationChanged");
                break;
            case (byte) 4:
                buffer.append("superseded");
                break;
            case (byte) 5:
                buffer.append("cessationOfOperation");
                break;
            case (byte) 6:
                buffer.append("certificateHold");
                break;
            case (byte) 8:
                buffer.append("removeFromCRL");
                break;
            case (byte) 9:
                buffer.append("privilegeWithdrawn");
                break;
            case (byte) 10:
                buffer.append("aACompromise");
                break;
        }
        buffer.append(" ]\n");
    }
}

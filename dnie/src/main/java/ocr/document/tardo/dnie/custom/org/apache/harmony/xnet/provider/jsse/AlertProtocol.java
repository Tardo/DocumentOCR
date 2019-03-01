package custom.org.apache.harmony.xnet.provider.jsse;

import custom.org.apache.harmony.xnet.provider.jsse.Logger.Stream;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.tls.CipherSuite;

public class AlertProtocol {
    protected static final byte ACCESS_DENIED = (byte) 49;
    protected static final byte BAD_CERTIFICATE = (byte) 42;
    protected static final byte BAD_RECORD_MAC = (byte) 20;
    protected static final byte CERTIFICATE_EXPIRED = (byte) 45;
    protected static final byte CERTIFICATE_REVOKED = (byte) 44;
    protected static final byte CERTIFICATE_UNKNOWN = (byte) 46;
    protected static final byte CLOSE_NOTIFY = (byte) 0;
    protected static final byte DECODE_ERROR = (byte) 50;
    protected static final byte DECOMPRESSION_FAILURE = (byte) 30;
    protected static final byte DECRYPTION_FAILED = (byte) 21;
    protected static final byte DECRYPT_ERROR = (byte) 51;
    protected static final byte EXPORT_RESTRICTION = (byte) 60;
    protected static final byte FATAL = (byte) 2;
    protected static final byte HANDSHAKE_FAILURE = (byte) 40;
    protected static final byte ILLEGAL_PARAMETER = (byte) 47;
    protected static final byte INSUFFICIENT_SECURITY = (byte) 71;
    protected static final byte INTERNAL_ERROR = (byte) 80;
    protected static final byte NO_RENEGOTIATION = (byte) 100;
    protected static final byte PROTOCOL_VERSION = (byte) 70;
    protected static final byte RECORD_OVERFLOW = (byte) 22;
    protected static final byte UNEXPECTED_MESSAGE = (byte) 10;
    protected static final byte UNKNOWN_CA = (byte) 48;
    protected static final byte UNSUPPORTED_CERTIFICATE = (byte) 43;
    protected static final byte USER_CANCELED = (byte) 90;
    protected static final byte WARNING = (byte) 1;
    private final byte[] alert = new byte[2];
    private Stream logger = Logger.getStream("alert");
    private SSLRecordProtocol recordProtocol;

    protected AlertProtocol() {
    }

    protected void setRecordProtocol(SSLRecordProtocol recordProtocol) {
        this.recordProtocol = recordProtocol;
    }

    protected void alert(byte level, byte description) {
        if (this.logger != null) {
            this.logger.println("Alert.alert: " + level + " " + description);
        }
        this.alert[0] = level;
        this.alert[1] = description;
    }

    protected byte getDescriptionCode() {
        return this.alert[0] != (byte) 0 ? this.alert[1] : (byte) -100;
    }

    protected void setProcessed() {
        if (this.logger != null) {
            this.logger.println("Alert.setProcessed");
        }
        this.alert[0] = (byte) 0;
    }

    protected boolean hasAlert() {
        return this.alert[0] != (byte) 0;
    }

    protected boolean isFatalAlert() {
        return this.alert[0] == (byte) 2;
    }

    protected String getAlertDescription() {
        switch (this.alert[1]) {
            case (byte) 0:
                return "close_notify";
            case (byte) 10:
                return "unexpected_message";
            case (byte) 20:
                return "bad_record_mac";
            case (byte) 21:
                return "decryption_failed";
            case (byte) 22:
                return "record_overflow";
            case (byte) 30:
                return "decompression_failure";
            case JPAKEParticipant.STATE_ROUND_2_VALIDATED /*40*/:
                return "handshake_failure";
            case (byte) 42:
                return "bad_certificate";
            case (byte) 43:
                return "unsupported_certificate";
            case (byte) 44:
                return "certificate_revoked";
            case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA /*45*/:
                return "certificate_expired";
            case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA /*46*/:
                return "certificate_unknown";
            case (byte) 47:
                return "illegal_parameter";
            case (byte) 48:
                return "unknown_ca";
            case (byte) 49:
                return "access_denied";
            case (byte) 50:
                return "decode_error";
            case (byte) 51:
                return "decrypt_error";
            case (byte) 60:
                return "export_restriction";
            case (byte) 70:
                return "protocol_version";
            case EACTags.CARD_CAPABILITIES /*71*/:
                return "insufficient_security";
            case EACTags.APPLICATION_LABEL /*80*/:
                return "internal_error";
            case EACTags.PRIMARY_ACCOUNT_NUMBER /*90*/:
                return "user_canceled";
            case EACTags.FMD_TEMPLATE /*100*/:
                return "no_renegotiation";
            default:
                return null;
        }
    }

    protected byte[] wrap() {
        return this.recordProtocol.wrap(DECRYPTION_FAILED, this.alert, 0, 2);
    }

    protected void shutdown() {
        this.alert[0] = (byte) 0;
        this.alert[1] = (byte) 0;
        this.recordProtocol = null;
    }
}

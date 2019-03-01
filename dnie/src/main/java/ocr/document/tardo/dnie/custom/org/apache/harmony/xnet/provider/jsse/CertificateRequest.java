package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;

public class CertificateRequest extends Message {
    public static final byte DSS_FIXED_DH = (byte) 4;
    public static final byte DSS_SIGN = (byte) 2;
    public static final byte RSA_FIXED_DH = (byte) 3;
    public static final byte RSA_SIGN = (byte) 1;
    X500Principal[] certificate_authorities;
    final byte[] certificate_types;
    private byte[][] encoded_principals;
    private String[] types;

    public CertificateRequest(byte[] certificate_types, X509Certificate[] accepted) {
        if (accepted == null) {
            fatalAlert((byte) 80, "CertificateRequest: array of certificate authority certificates is null");
        }
        this.certificate_types = certificate_types;
        int totalPrincipalsLength = 0;
        this.certificate_authorities = new X500Principal[accepted.length];
        this.encoded_principals = new byte[accepted.length][];
        for (int i = 0; i < accepted.length; i++) {
            this.certificate_authorities[i] = accepted[i].getIssuerX500Principal();
            this.encoded_principals[i] = this.certificate_authorities[i].getEncoded();
            totalPrincipalsLength += this.encoded_principals[i].length + 2;
        }
        this.length = (certificate_types.length + 3) + totalPrincipalsLength;
    }

    public CertificateRequest(HandshakeIODataStream in, int length) throws IOException {
        int size = in.readUint8();
        this.certificate_types = new byte[size];
        in.read(this.certificate_types, 0, size);
        size = in.readUint16();
        this.certificate_authorities = new X500Principal[size];
        int totalPrincipalsLength = 0;
        Vector<X500Principal> principals = new Vector();
        while (totalPrincipalsLength < size) {
            int principalLength = in.readUint16();
            principals.add(new X500Principal(in));
            totalPrincipalsLength = (totalPrincipalsLength + 2) + principalLength;
        }
        this.certificate_authorities = new X500Principal[principals.size()];
        for (int i = 0; i < this.certificate_authorities.length; i++) {
            this.certificate_authorities[i] = (X500Principal) principals.elementAt(i);
        }
        this.length = (this.certificate_types.length + 3) + totalPrincipalsLength;
        if (this.length != length) {
            fatalAlert((byte) 50, "DECODE ERROR: incorrect CertificateRequest");
        }
    }

    public void send(HandshakeIODataStream out) {
        int i;
        out.writeUint8((long) this.certificate_types.length);
        for (byte write : this.certificate_types) {
            out.write(write);
        }
        int authoritiesLength = 0;
        for (i = 0; i < this.certificate_authorities.length; i++) {
            authoritiesLength += this.encoded_principals[i].length + 2;
        }
        out.writeUint16((long) authoritiesLength);
        for (i = 0; i < this.certificate_authorities.length; i++) {
            out.writeUint16((long) this.encoded_principals[i].length);
            out.write(this.encoded_principals[i]);
        }
    }

    public int getType() {
        return 13;
    }

    public String[] getTypesAsString() {
        if (this.types == null) {
            this.types = new String[this.certificate_types.length];
            for (int i = 0; i < this.types.length; i++) {
                switch (this.certificate_types[i]) {
                    case (byte) 1:
                        this.types[i] = "RSA";
                        break;
                    case (byte) 2:
                        this.types[i] = "DSA";
                        break;
                    case (byte) 3:
                        this.types[i] = "DH_RSA";
                        break;
                    case (byte) 4:
                        this.types[i] = "DH_DSA";
                        break;
                    default:
                        this.types[i] = "UNSUPPORTED";
                        break;
                }
            }
        }
        return this.types;
    }
}

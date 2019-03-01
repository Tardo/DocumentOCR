package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.lang.reflect.Array;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Vector;

public class CertificateMessage extends Message {
    X509Certificate[] certs;
    byte[][] encoded_certs;

    public CertificateMessage(HandshakeIODataStream in, int length) throws IOException {
        int l = in.readUint24();
        if (l == 0) {
            if (length != 3) {
                fatalAlert((byte) 50, "DECODE ERROR: incorrect CertificateMessage");
            }
            this.certs = new X509Certificate[0];
            this.encoded_certs = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{0, 0});
            this.length = 3;
            return;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            Vector<Certificate> certs_vector = new Vector();
            int enc_size = 0;
            while (l > 0) {
                int size = in.readUint24();
                l -= 3;
                try {
                    certs_vector.add(cf.generateCertificate(in));
                } catch (CertificateException e) {
                    fatalAlert((byte) 50, "DECODE ERROR", e);
                }
                l -= size;
                enc_size += size;
            }
            this.certs = new X509Certificate[certs_vector.size()];
            for (int i = 0; i < this.certs.length; i++) {
                this.certs[i] = (X509Certificate) certs_vector.elementAt(i);
            }
            this.length = ((this.certs.length * 3) + 3) + enc_size;
            if (this.length != length) {
                fatalAlert((byte) 50, "DECODE ERROR: incorrect CertificateMessage");
            }
        } catch (CertificateException e2) {
            fatalAlert((byte) 80, "INTERNAL ERROR", e2);
        }
    }

    public CertificateMessage(X509Certificate[] certs) {
        if (certs == null) {
            this.certs = new X509Certificate[0];
            this.encoded_certs = (byte[][]) Array.newInstance(Byte.TYPE, new int[]{0, 0});
            this.length = 3;
            return;
        }
        int i;
        this.certs = certs;
        if (this.encoded_certs == null) {
            this.encoded_certs = new byte[certs.length][];
            for (i = 0; i < certs.length; i++) {
                try {
                    this.encoded_certs[i] = certs[i].getEncoded();
                } catch (CertificateEncodingException e) {
                    fatalAlert((byte) 80, "INTERNAL ERROR", e);
                }
            }
        }
        this.length = (this.encoded_certs.length * 3) + 3;
        for (byte[] length : this.encoded_certs) {
            this.length += length.length;
        }
    }

    public void send(HandshakeIODataStream out) {
        int i;
        if (this.encoded_certs == null) {
            this.encoded_certs = new byte[this.certs.length][];
            for (i = 0; i < this.certs.length; i++) {
                try {
                    this.encoded_certs[i] = this.certs[i].getEncoded();
                } catch (CertificateEncodingException e) {
                    fatalAlert((byte) 80, "INTERNAL ERROR", e);
                }
            }
        }
        int total_length = this.encoded_certs.length * 3;
        for (byte[] length : this.encoded_certs) {
            total_length += length.length;
        }
        out.writeUint24((long) total_length);
        for (i = 0; i < this.encoded_certs.length; i++) {
            out.writeUint24((long) this.encoded_certs[i].length);
            out.write(this.encoded_certs[i]);
        }
    }

    public int getType() {
        return 11;
    }
}

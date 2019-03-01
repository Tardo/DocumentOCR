package custom.org.apache.harmony.security.provider.cert;

import custom.org.apache.harmony.security.asn1.ASN1Any;
import custom.org.apache.harmony.security.asn1.ASN1Explicit;
import custom.org.apache.harmony.security.asn1.ASN1Implicit;
import custom.org.apache.harmony.security.asn1.ASN1Oid;
import custom.org.apache.harmony.security.asn1.ASN1Sequence;
import custom.org.apache.harmony.security.asn1.ASN1SequenceOf;
import custom.org.apache.harmony.security.asn1.ASN1Type;
import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.pkcs7.ContentInfo;
import custom.org.apache.harmony.security.pkcs7.SignedData;
import custom.org.apache.harmony.security.x509.Certificate;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertPath;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class X509CertPathImpl extends CertPath {
    public static final ASN1SequenceOf ASN1 = new ASN1SequenceOf(ASN1Any.getInstance()) {
        public Object getDecodedObject(BerInputStream in) throws IOException {
            List encodings = in.content;
            int size = encodings.size();
            List certificates = new ArrayList(size);
            for (int i = 0; i < size; i++) {
                certificates.add(new X509CertImpl((Certificate) Certificate.ASN1.decode((byte[]) encodings.get(i))));
            }
            return new X509CertPathImpl(certificates, 0, in.getEncoded());
        }

        public Collection getValues(Object object) {
            X509CertPathImpl cp = (X509CertPathImpl) object;
            if (cp.certificates == null) {
                return new ArrayList();
            }
            int size = cp.certificates.size();
            Collection encodings = new ArrayList(size);
            int i = 0;
            while (i < size) {
                try {
                    encodings.add(((X509Certificate) cp.certificates.get(i)).getEncoded());
                    i++;
                } catch (CertificateEncodingException e) {
                    throw new IllegalArgumentException(Messages.getString("security.161"));
                }
            }
            return encodings;
        }
    };
    private static final ASN1Sequence ASN1_SIGNED_DATA = new ASN1Sequence(new ASN1Type[]{ASN1Any.getInstance(), new ASN1Implicit(0, ASN1), ASN1Any.getInstance()}) {
        private final byte[] PRECALCULATED_HEAD = new byte[]{(byte) 2, (byte) 1, (byte) 1, (byte) 49, (byte) 0, (byte) 48, (byte) 3, (byte) 6, (byte) 1, (byte) 0};
        private final byte[] SIGNERS_INFO = new byte[]{(byte) 49, (byte) 0};

        protected void getValues(Object object, Object[] values) {
            values[0] = this.PRECALCULATED_HEAD;
            values[1] = object;
            values[2] = this.SIGNERS_INFO;
        }

        public Object decode(BerInputStream in) throws IOException {
            throw new RuntimeException("Invalid use of encoder for PKCS#7 SignedData object");
        }
    };
    public static final int PKCS7 = 1;
    private static final ASN1Sequence PKCS7_SIGNED_DATA_OBJECT = new ASN1Sequence(new ASN1Type[]{ASN1Any.getInstance(), new ASN1Explicit(0, ASN1_SIGNED_DATA)}) {
        private final byte[] SIGNED_DATA_OID = ASN1Oid.getInstance().encode(ContentInfo.SIGNED_DATA);

        protected void getValues(Object object, Object[] values) {
            values[0] = this.SIGNED_DATA_OID;
            values[1] = object;
        }

        public Object decode(BerInputStream in) throws IOException {
            throw new RuntimeException("Invalid use of encoder for PKCS#7 SignedData object");
        }
    };
    public static final int PKI_PATH = 0;
    static final List encodings = Collections.unmodifiableList(Arrays.asList(encodingsArr));
    private static final String[] encodingsArr = new String[]{"PkiPath", "PKCS7"};
    private static final long serialVersionUID = 7989755106209515436L;
    private final List certificates;
    private byte[] pkcs7Encoding;
    private byte[] pkiPathEncoding;

    public X509CertPathImpl(List certs) throws CertificateException {
        super("X.509");
        int size = certs.size();
        this.certificates = new ArrayList(size);
        int i = 0;
        while (i < size) {
            Object cert = certs.get(i);
            if (cert instanceof X509Certificate) {
                this.certificates.add(cert);
                i++;
            } else {
                throw new CertificateException(Messages.getString("security.15D"));
            }
        }
    }

    private X509CertPathImpl(List certs, int type, byte[] encoding) {
        super("X.509");
        if (type == 0) {
            this.pkiPathEncoding = encoding;
        } else {
            this.pkcs7Encoding = encoding;
        }
        this.certificates = certs;
    }

    public static X509CertPathImpl getInstance(InputStream in) throws CertificateException {
        try {
            return (X509CertPathImpl) ASN1.decode(in);
        } catch (IOException e) {
            throw new CertificateException(Messages.getString("security.15E", e.getMessage()));
        }
    }

    public static X509CertPathImpl getInstance(InputStream in, String encoding) throws CertificateException {
        if (encodings.contains(encoding)) {
            try {
                if (encodingsArr[0].equals(encoding)) {
                    return (X509CertPathImpl) ASN1.decode(in);
                }
                ContentInfo ci = (ContentInfo) ContentInfo.ASN1.decode(in);
                SignedData sd = ci.getSignedData();
                if (sd == null) {
                    throw new CertificateException(Messages.getString("security.160"));
                }
                List certs = sd.getCertificates();
                if (certs == null) {
                    certs = new ArrayList();
                }
                List result = new ArrayList();
                for (int i = 0; i < certs.size(); i++) {
                    result.add(new X509CertImpl((Certificate) certs.get(i)));
                }
                return new X509CertPathImpl(result, 1, ci.getEncoded());
            } catch (IOException e) {
                throw new CertificateException(Messages.getString("security.15E", e.getMessage()));
            }
        }
        throw new CertificateException(Messages.getString("security.15F", (Object) encoding));
    }

    public static X509CertPathImpl getInstance(byte[] in) throws CertificateException {
        try {
            return (X509CertPathImpl) ASN1.decode(in);
        } catch (IOException e) {
            throw new CertificateException(Messages.getString("security.15E", e.getMessage()));
        }
    }

    public static X509CertPathImpl getInstance(byte[] in, String encoding) throws CertificateException {
        if (encodings.contains(encoding)) {
            try {
                if (encodingsArr[0].equals(encoding)) {
                    return (X509CertPathImpl) ASN1.decode(in);
                }
                ContentInfo ci = (ContentInfo) ContentInfo.ASN1.decode(in);
                SignedData sd = ci.getSignedData();
                if (sd == null) {
                    throw new CertificateException(Messages.getString("security.160"));
                }
                List certs = sd.getCertificates();
                if (certs == null) {
                    certs = new ArrayList();
                }
                List result = new ArrayList();
                for (int i = 0; i < certs.size(); i++) {
                    result.add(new X509CertImpl((Certificate) certs.get(i)));
                }
                return new X509CertPathImpl(result, 1, ci.getEncoded());
            } catch (IOException e) {
                throw new CertificateException(Messages.getString("security.15E", e.getMessage()));
            }
        }
        throw new CertificateException(Messages.getString("security.15F", (Object) encoding));
    }

    public List getCertificates() {
        return Collections.unmodifiableList(this.certificates);
    }

    public byte[] getEncoded() throws CertificateEncodingException {
        if (this.pkiPathEncoding == null) {
            this.pkiPathEncoding = ASN1.encode(this);
        }
        byte[] result = new byte[this.pkiPathEncoding.length];
        System.arraycopy(this.pkiPathEncoding, 0, result, 0, this.pkiPathEncoding.length);
        return result;
    }

    public byte[] getEncoded(String encoding) throws CertificateEncodingException {
        if (!encodings.contains(encoding)) {
            throw new CertificateEncodingException(Messages.getString("security.15F", (Object) encoding));
        } else if (encodingsArr[0].equals(encoding)) {
            return getEncoded();
        } else {
            if (this.pkcs7Encoding == null) {
                this.pkcs7Encoding = PKCS7_SIGNED_DATA_OBJECT.encode(this);
            }
            byte[] result = new byte[this.pkcs7Encoding.length];
            System.arraycopy(this.pkcs7Encoding, 0, result, 0, this.pkcs7Encoding.length);
            return result;
        }
    }

    public Iterator getEncodings() {
        return encodings.iterator();
    }
}

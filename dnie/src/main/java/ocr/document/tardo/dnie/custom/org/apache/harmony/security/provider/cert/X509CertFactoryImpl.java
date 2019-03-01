package custom.org.apache.harmony.security.provider.cert;

import custom.org.apache.harmony.security.asn1.BerInputStream;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.security.cert.X509CRL;
import java.util.Iterator;
import java.util.List;

public class X509CertFactoryImpl extends CertificateFactorySpi {
    private static byte[] CERT_BOUND_SUFFIX;
    private static Cache CERT_CACHE = new Cache(CERT_CACHE_SEED_LENGTH);
    private static int CERT_CACHE_SEED_LENGTH = 28;
    private static Cache CRL_CACHE = new Cache(CRL_CACHE_SEED_LENGTH);
    private static int CRL_CACHE_SEED_LENGTH = 24;
    private static byte[] FREE_BOUND_SUFFIX = null;
    private static byte[] pemBegin;
    private static byte[] pemClose;

    private static class RestoringInputStream extends InputStream {
        private static final int BUFF_SIZE = 32;
        private int bar = 0;
        private final int[] buff = new int[64];
        private int end = 0;
        private final InputStream inStream;
        private int pos = -1;

        public RestoringInputStream(InputStream inStream) {
            this.inStream = inStream;
        }

        public int available() throws IOException {
            return (this.bar - this.pos) + this.inStream.available();
        }

        public void close() throws IOException {
            this.inStream.close();
        }

        public void mark(int readlimit) {
            if (this.pos < 0) {
                this.pos = 0;
                this.bar = 0;
                this.end = 31;
                return;
            }
            this.end = ((this.pos + 32) - 1) % 32;
        }

        public boolean markSupported() {
            return true;
        }

        public int read() throws IOException {
            if (this.pos >= 0) {
                int cur = this.pos % 32;
                if (cur < this.bar) {
                    this.pos++;
                    return this.buff[cur];
                } else if (cur != this.end) {
                    this.buff[cur] = this.inStream.read();
                    this.bar = cur + 1;
                    this.pos++;
                    return this.buff[cur];
                } else {
                    this.pos = -1;
                }
            }
            return this.inStream.read();
        }

        public int read(byte[] b) throws IOException {
            return read(b, 0, b.length);
        }

        public int read(byte[] b, int off, int len) throws IOException {
            int i = 0;
            while (i < len) {
                int read_b = read();
                if (read_b != -1) {
                    b[off + i] = (byte) read_b;
                    i++;
                } else if (i == 0) {
                    return -1;
                } else {
                    return i;
                }
            }
            return i;
        }

        public void reset() throws IOException {
            if (this.pos >= 0) {
                this.pos = (this.end + 1) % 32;
                return;
            }
            throw new IOException(Messages.getString("security.15A"));
        }

        public long skip(long n) throws IOException {
            if (this.pos < 0) {
                return this.inStream.skip(n);
            }
            long i = 0;
            int av = available();
            if (((long) av) < n) {
                n = (long) av;
            }
            while (i < n && read() != -1) {
                i++;
            }
            return i;
        }
    }

    static {
        try {
            pemBegin = "-----BEGIN".getBytes("UTF-8");
            pemClose = "-----END".getBytes("UTF-8");
            CERT_BOUND_SUFFIX = " CERTIFICATE-----".getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public Certificate engineGenerateCertificate(InputStream inStream) throws CertificateException {
        if (inStream == null) {
            throw new CertificateException(Messages.getString("security.153"));
        }
        try {
            if (!inStream.markSupported()) {
                inStream = new RestoringInputStream(inStream);
            }
            inStream.mark(1);
            if (inStream.read() == 45) {
                return getCertificate(decodePEM(inStream, CERT_BOUND_SUFFIX));
            }
            inStream.reset();
            return getCertificate(inStream);
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public java.util.Collection<? extends java.security.cert.Certificate> engineGenerateCertificates(java.io.InputStream r16) throws java.security.cert.CertificateException {
        /*
        r15 = this;
        r14 = 48;
        r13 = -1;
        if (r16 != 0) goto L_0x0011;
    L_0x0005:
        r12 = new java.security.cert.CertificateException;
        r13 = "security.153";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);
        r12.<init>(r13);
        throw r12;
    L_0x0011:
        r10 = new java.util.ArrayList;
        r10.<init>();
        r12 = r16.markSupported();	 Catch:{ IOException -> 0x006e }
        if (r12 != 0) goto L_0x0025;
    L_0x001c:
        r8 = new custom.org.apache.harmony.security.provider.cert.X509CertFactoryImpl$RestoringInputStream;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r8.<init>(r0);	 Catch:{ IOException -> 0x006e }
        r16 = r8;
    L_0x0025:
        r5 = 0;
        r11 = -1;
        r12 = 1;
        r0 = r16;
        r0.mark(r12);	 Catch:{ IOException -> 0x006e }
    L_0x002d:
        r2 = r16.read();	 Catch:{ IOException -> 0x006e }
        if (r2 == r13) goto L_0x0059;
    L_0x0033:
        r12 = 45;
        if (r2 != r12) goto L_0x0060;
    L_0x0037:
        r12 = FREE_BOUND_SUFFIX;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r5 = r15.decodePEM(r0, r12);	 Catch:{ IOException -> 0x006e }
    L_0x003f:
        if (r5 != 0) goto L_0x008b;
    L_0x0041:
        r7 = new custom.org.apache.harmony.security.asn1.BerInputStream;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r7.<init>(r0);	 Catch:{ IOException -> 0x006e }
    L_0x0048:
        r11 = r7.next();	 Catch:{ IOException -> 0x006e }
        if (r5 != 0) goto L_0x0051;
    L_0x004e:
        r16.reset();	 Catch:{ IOException -> 0x006e }
    L_0x0051:
        if (r11 == r14) goto L_0x0091;
    L_0x0053:
        r12 = r10.size();	 Catch:{ IOException -> 0x006e }
        if (r12 != 0) goto L_0x005f;
    L_0x0059:
        r12 = r10.size();	 Catch:{ IOException -> 0x006e }
        if (r12 == 0) goto L_0x00a9;
    L_0x005f:
        return r10;
    L_0x0060:
        if (r2 != r14) goto L_0x0075;
    L_0x0062:
        r5 = 0;
        r16.reset();	 Catch:{ IOException -> 0x006e }
        r12 = CERT_CACHE_SEED_LENGTH;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r0.mark(r12);	 Catch:{ IOException -> 0x006e }
        goto L_0x003f;
    L_0x006e:
        r4 = move-exception;
        r12 = new java.security.cert.CertificateException;
        r12.<init>(r4);
        throw r12;
    L_0x0075:
        r12 = r10.size();	 Catch:{ IOException -> 0x006e }
        if (r12 != 0) goto L_0x0087;
    L_0x007b:
        r12 = new java.security.cert.CertificateException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.15F";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
    L_0x0087:
        r16.reset();	 Catch:{ IOException -> 0x006e }
        goto L_0x005f;
    L_0x008b:
        r7 = new custom.org.apache.harmony.security.asn1.BerInputStream;	 Catch:{ IOException -> 0x006e }
        r7.<init>(r5);	 Catch:{ IOException -> 0x006e }
        goto L_0x0048;
    L_0x0091:
        if (r5 != 0) goto L_0x00a1;
    L_0x0093:
        r12 = getCertificate(r16);	 Catch:{ IOException -> 0x006e }
        r10.add(r12);	 Catch:{ IOException -> 0x006e }
    L_0x009a:
        r12 = 1;
        r0 = r16;
        r0.mark(r12);	 Catch:{ IOException -> 0x006e }
        goto L_0x002d;
    L_0x00a1:
        r12 = getCertificate(r5);	 Catch:{ IOException -> 0x006e }
        r10.add(r12);	 Catch:{ IOException -> 0x006e }
        goto L_0x009a;
    L_0x00a9:
        if (r2 != r13) goto L_0x00b7;
    L_0x00ab:
        r12 = new java.security.cert.CertificateException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.155";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
    L_0x00b7:
        r12 = 6;
        if (r11 != r12) goto L_0x0101;
    L_0x00ba:
        if (r5 == 0) goto L_0x00da;
    L_0x00bc:
        r12 = custom.org.apache.harmony.security.pkcs7.ContentInfo.ASN1;	 Catch:{ IOException -> 0x006e }
        r12 = r12.decode(r5);	 Catch:{ IOException -> 0x006e }
    L_0x00c2:
        r12 = (custom.org.apache.harmony.security.pkcs7.ContentInfo) r12;	 Catch:{ IOException -> 0x006e }
        r0 = r12;
        r0 = (custom.org.apache.harmony.security.pkcs7.ContentInfo) r0;	 Catch:{ IOException -> 0x006e }
        r9 = r0;
        r3 = r9.getSignedData();	 Catch:{ IOException -> 0x006e }
        if (r3 != 0) goto L_0x00e3;
    L_0x00ce:
        r12 = new java.security.cert.CertificateException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.154";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
    L_0x00da:
        r12 = custom.org.apache.harmony.security.pkcs7.ContentInfo.ASN1;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r12 = r12.decode(r0);	 Catch:{ IOException -> 0x006e }
        goto L_0x00c2;
    L_0x00e3:
        r1 = r3.getCertificates();	 Catch:{ IOException -> 0x006e }
        if (r1 == 0) goto L_0x005f;
    L_0x00e9:
        r6 = 0;
    L_0x00ea:
        r12 = r1.size();	 Catch:{ IOException -> 0x006e }
        if (r6 >= r12) goto L_0x005f;
    L_0x00f0:
        r13 = new custom.org.apache.harmony.security.provider.cert.X509CertImpl;	 Catch:{ IOException -> 0x006e }
        r12 = r1.get(r6);	 Catch:{ IOException -> 0x006e }
        r12 = (custom.org.apache.harmony.security.x509.Certificate) r12;	 Catch:{ IOException -> 0x006e }
        r13.<init>(r12);	 Catch:{ IOException -> 0x006e }
        r10.add(r13);	 Catch:{ IOException -> 0x006e }
        r6 = r6 + 1;
        goto L_0x00ea;
    L_0x0101:
        r12 = new java.security.cert.CertificateException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.15F";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
        */
        throw new UnsupportedOperationException("Method not decompiled: custom.org.apache.harmony.security.provider.cert.X509CertFactoryImpl.engineGenerateCertificates(java.io.InputStream):java.util.Collection<? extends java.security.cert.Certificate>");
    }

    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        if (inStream == null) {
            throw new CRLException(Messages.getString("security.153"));
        }
        try {
            if (!inStream.markSupported()) {
                inStream = new RestoringInputStream(inStream);
            }
            inStream.mark(1);
            if (inStream.read() == 45) {
                return getCRL(decodePEM(inStream, FREE_BOUND_SUFFIX));
            }
            inStream.reset();
            return getCRL(inStream);
        } catch (IOException e) {
            throw new CRLException(e);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public java.util.Collection<? extends java.security.cert.CRL> engineGenerateCRLs(java.io.InputStream r16) throws java.security.cert.CRLException {
        /*
        r15 = this;
        r14 = 48;
        r13 = -1;
        if (r16 != 0) goto L_0x0011;
    L_0x0005:
        r12 = new java.security.cert.CRLException;
        r13 = "security.153";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);
        r12.<init>(r13);
        throw r12;
    L_0x0011:
        r10 = new java.util.ArrayList;
        r10.<init>();
        r12 = r16.markSupported();	 Catch:{ IOException -> 0x006e }
        if (r12 != 0) goto L_0x0025;
    L_0x001c:
        r8 = new custom.org.apache.harmony.security.provider.cert.X509CertFactoryImpl$RestoringInputStream;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r8.<init>(r0);	 Catch:{ IOException -> 0x006e }
        r16 = r8;
    L_0x0025:
        r5 = 0;
        r11 = -1;
        r12 = 1;
        r0 = r16;
        r0.mark(r12);	 Catch:{ IOException -> 0x006e }
    L_0x002d:
        r1 = r16.read();	 Catch:{ IOException -> 0x006e }
        if (r1 == r13) goto L_0x0059;
    L_0x0033:
        r12 = 45;
        if (r1 != r12) goto L_0x0060;
    L_0x0037:
        r12 = FREE_BOUND_SUFFIX;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r5 = r15.decodePEM(r0, r12);	 Catch:{ IOException -> 0x006e }
    L_0x003f:
        if (r5 != 0) goto L_0x008b;
    L_0x0041:
        r7 = new custom.org.apache.harmony.security.asn1.BerInputStream;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r7.<init>(r0);	 Catch:{ IOException -> 0x006e }
    L_0x0048:
        r11 = r7.next();	 Catch:{ IOException -> 0x006e }
        if (r5 != 0) goto L_0x0051;
    L_0x004e:
        r16.reset();	 Catch:{ IOException -> 0x006e }
    L_0x0051:
        if (r11 == r14) goto L_0x0091;
    L_0x0053:
        r12 = r10.size();	 Catch:{ IOException -> 0x006e }
        if (r12 != 0) goto L_0x005f;
    L_0x0059:
        r12 = r10.size();	 Catch:{ IOException -> 0x006e }
        if (r12 == 0) goto L_0x00a9;
    L_0x005f:
        return r10;
    L_0x0060:
        if (r1 != r14) goto L_0x0075;
    L_0x0062:
        r5 = 0;
        r16.reset();	 Catch:{ IOException -> 0x006e }
        r12 = CRL_CACHE_SEED_LENGTH;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r0.mark(r12);	 Catch:{ IOException -> 0x006e }
        goto L_0x003f;
    L_0x006e:
        r4 = move-exception;
        r12 = new java.security.cert.CRLException;
        r12.<init>(r4);
        throw r12;
    L_0x0075:
        r12 = r10.size();	 Catch:{ IOException -> 0x006e }
        if (r12 != 0) goto L_0x0087;
    L_0x007b:
        r12 = new java.security.cert.CRLException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.15F";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
    L_0x0087:
        r16.reset();	 Catch:{ IOException -> 0x006e }
        goto L_0x005f;
    L_0x008b:
        r7 = new custom.org.apache.harmony.security.asn1.BerInputStream;	 Catch:{ IOException -> 0x006e }
        r7.<init>(r5);	 Catch:{ IOException -> 0x006e }
        goto L_0x0048;
    L_0x0091:
        if (r5 != 0) goto L_0x00a1;
    L_0x0093:
        r12 = getCRL(r16);	 Catch:{ IOException -> 0x006e }
        r10.add(r12);	 Catch:{ IOException -> 0x006e }
    L_0x009a:
        r12 = 1;
        r0 = r16;
        r0.mark(r12);	 Catch:{ IOException -> 0x006e }
        goto L_0x002d;
    L_0x00a1:
        r12 = getCRL(r5);	 Catch:{ IOException -> 0x006e }
        r10.add(r12);	 Catch:{ IOException -> 0x006e }
        goto L_0x009a;
    L_0x00a9:
        if (r1 != r13) goto L_0x00b7;
    L_0x00ab:
        r12 = new java.security.cert.CRLException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.155";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
    L_0x00b7:
        r12 = 6;
        if (r11 != r12) goto L_0x0101;
    L_0x00ba:
        if (r5 == 0) goto L_0x00da;
    L_0x00bc:
        r12 = custom.org.apache.harmony.security.pkcs7.ContentInfo.ASN1;	 Catch:{ IOException -> 0x006e }
        r12 = r12.decode(r5);	 Catch:{ IOException -> 0x006e }
    L_0x00c2:
        r12 = (custom.org.apache.harmony.security.pkcs7.ContentInfo) r12;	 Catch:{ IOException -> 0x006e }
        r0 = r12;
        r0 = (custom.org.apache.harmony.security.pkcs7.ContentInfo) r0;	 Catch:{ IOException -> 0x006e }
        r9 = r0;
        r3 = r9.getSignedData();	 Catch:{ IOException -> 0x006e }
        if (r3 != 0) goto L_0x00e3;
    L_0x00ce:
        r12 = new java.security.cert.CRLException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.154";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
    L_0x00da:
        r12 = custom.org.apache.harmony.security.pkcs7.ContentInfo.ASN1;	 Catch:{ IOException -> 0x006e }
        r0 = r16;
        r12 = r12.decode(r0);	 Catch:{ IOException -> 0x006e }
        goto L_0x00c2;
    L_0x00e3:
        r2 = r3.getCRLs();	 Catch:{ IOException -> 0x006e }
        if (r2 == 0) goto L_0x005f;
    L_0x00e9:
        r6 = 0;
    L_0x00ea:
        r12 = r2.size();	 Catch:{ IOException -> 0x006e }
        if (r6 >= r12) goto L_0x005f;
    L_0x00f0:
        r13 = new custom.org.apache.harmony.security.provider.cert.X509CRLImpl;	 Catch:{ IOException -> 0x006e }
        r12 = r2.get(r6);	 Catch:{ IOException -> 0x006e }
        r12 = (custom.org.apache.harmony.security.x509.CertificateList) r12;	 Catch:{ IOException -> 0x006e }
        r13.<init>(r12);	 Catch:{ IOException -> 0x006e }
        r10.add(r13);	 Catch:{ IOException -> 0x006e }
        r6 = r6 + 1;
        goto L_0x00ea;
    L_0x0101:
        r12 = new java.security.cert.CRLException;	 Catch:{ IOException -> 0x006e }
        r13 = "security.15F";
        r13 = custom.org.apache.harmony.security.internal.nls.Messages.getString(r13);	 Catch:{ IOException -> 0x006e }
        r12.<init>(r13);	 Catch:{ IOException -> 0x006e }
        throw r12;	 Catch:{ IOException -> 0x006e }
        */
        throw new UnsupportedOperationException("Method not decompiled: custom.org.apache.harmony.security.provider.cert.X509CertFactoryImpl.engineGenerateCRLs(java.io.InputStream):java.util.Collection<? extends java.security.cert.CRL>");
    }

    public CertPath engineGenerateCertPath(InputStream inStream) throws CertificateException {
        if (inStream != null) {
            return engineGenerateCertPath(inStream, "PkiPath");
        }
        throw new CertificateException(Messages.getString("security.153"));
    }

    public CertPath engineGenerateCertPath(InputStream inStream, String encoding) throws CertificateException {
        if (inStream == null) {
            throw new CertificateException(Messages.getString("security.153"));
        }
        if (!inStream.markSupported()) {
            inStream = new RestoringInputStream(inStream);
        }
        try {
            inStream.mark(1);
            int ch = inStream.read();
            if (ch == 45) {
                return X509CertPathImpl.getInstance(decodePEM(inStream, FREE_BOUND_SUFFIX), encoding);
            }
            if (ch == 48) {
                inStream.reset();
                return X509CertPathImpl.getInstance(inStream, encoding);
            }
            throw new CertificateException(Messages.getString("security.15F"));
        } catch (IOException e) {
            throw new CertificateException(e);
        }
    }

    public CertPath engineGenerateCertPath(List certificates) throws CertificateException {
        return new X509CertPathImpl(certificates);
    }

    public Iterator<String> engineGetCertPathEncodings() {
        return X509CertPathImpl.encodings.iterator();
    }

    private byte[] decodePEM(InputStream inStream, byte[] boundary_suffix) throws IOException {
        int i;
        for (i = 1; i < pemBegin.length; i++) {
            if (pemBegin[i] != inStream.read()) {
                throw new IOException("Incorrect PEM encoding: '-----BEGIN" + (boundary_suffix == null ? "" : new String(boundary_suffix)) + "' is expected as opening delimiter boundary.");
            }
        }
        int ch;
        if (boundary_suffix == null) {
            do {
                ch = inStream.read();
                if (ch != 10) {
                }
            } while (ch != -1);
            throw new IOException(Messages.getString("security.156"));
        }
        for (byte b : boundary_suffix) {
            if (b != inStream.read()) {
                throw new IOException(Messages.getString("security.15B", new String(boundary_suffix)));
            }
        }
        ch = inStream.read();
        if (ch == 13) {
            ch = inStream.read();
        }
        if (ch != 10) {
            throw new IOException(Messages.getString("security.15B2"));
        }
        int size = 1024;
        byte[] buff = new byte[1024];
        int index = 0;
        while (true) {
            ch = inStream.read();
            if (ch == 45) {
                break;
            } else if (ch == -1) {
                throw new IOException(Messages.getString("security.157"));
            } else {
                int index2 = index + 1;
                buff[index] = (byte) ch;
                if (index2 == size) {
                    byte[] newbuff = new byte[(size + 1024)];
                    System.arraycopy(buff, 0, newbuff, 0, size);
                    buff = newbuff;
                    size += 1024;
                    index = index2;
                } else {
                    index = index2;
                }
            }
        }
        if (buff[index - 1] != (byte) 10) {
            throw new IOException(Messages.getString("security.158"));
        }
        for (i = 1; i < pemClose.length; i++) {
            if (pemClose[i] != inStream.read()) {
                throw new IOException(Messages.getString("security.15B1", boundary_suffix == null ? "" : new String(boundary_suffix)));
            }
        }
        if (boundary_suffix == null) {
            do {
                ch = inStream.read();
                if (ch == -1 || ch == 10) {
                    break;
                }
            } while (ch != 13);
        } else {
            for (byte b2 : boundary_suffix) {
                if (b2 != inStream.read()) {
                    throw new IOException(Messages.getString("security.15B1", new String(boundary_suffix)));
                }
            }
        }
        inStream.mark(1);
        while (true) {
            ch = inStream.read();
            if (ch == -1 || !(ch == 10 || ch == 13)) {
                inStream.reset();
                buff = decode(buff, index);
            } else {
                inStream.mark(1);
            }
        }
        inStream.reset();
        buff = decode(buff, index);
        if (buff != null) {
            return buff;
        }
        throw new IOException(Messages.getString("security.159"));
    }

    private static byte[] readBytes(InputStream source, int length) throws IOException {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++) {
            int bytik = source.read();
            if (bytik == -1) {
                return null;
            }
            result[i] = (byte) bytik;
        }
        return result;
    }

    private static Certificate getCertificate(byte[] encoding) throws CertificateException, IOException {
        if (encoding.length < CERT_CACHE_SEED_LENGTH) {
            throw new CertificateException(Messages.getString("security.152"));
        }
        synchronized (CERT_CACHE) {
            Certificate res;
            long hash = CERT_CACHE.getHash(encoding);
            if (CERT_CACHE.contains(hash)) {
                res = (Certificate) CERT_CACHE.get(hash, encoding);
                if (res != null) {
                    return res;
                }
            }
            res = new X509CertImpl(encoding);
            CERT_CACHE.put(hash, encoding, res);
            return res;
        }
    }

    private static Certificate getCertificate(InputStream inStream) throws CertificateException, IOException {
        Certificate res;
        synchronized (CERT_CACHE) {
            inStream.mark(CERT_CACHE_SEED_LENGTH);
            byte[] buff = readBytes(inStream, CERT_CACHE_SEED_LENGTH);
            inStream.reset();
            if (buff == null) {
                throw new CertificateException(Messages.getString("security.152"));
            }
            long hash = CERT_CACHE.getHash(buff);
            if (CERT_CACHE.contains(hash)) {
                byte[] encoding = new byte[BerInputStream.getLength(buff)];
                if (encoding.length < CERT_CACHE_SEED_LENGTH) {
                    throw new CertificateException(Messages.getString("security.15B3"));
                }
                inStream.read(encoding);
                res = (Certificate) CERT_CACHE.get(hash, encoding);
                if (res != null) {
                } else {
                    res = new X509CertImpl(encoding);
                    CERT_CACHE.put(hash, encoding, res);
                }
            } else {
                inStream.reset();
                res = new X509CertImpl(inStream);
                CERT_CACHE.put(hash, res.getEncoded(), res);
            }
        }
        return res;
    }

    private static CRL getCRL(byte[] encoding) throws CRLException, IOException {
        if (encoding.length < CRL_CACHE_SEED_LENGTH) {
            throw new CRLException(Messages.getString("security.152"));
        }
        synchronized (CRL_CACHE) {
            X509CRL res;
            long hash = CRL_CACHE.getHash(encoding);
            if (CRL_CACHE.contains(hash)) {
                res = (X509CRL) CRL_CACHE.get(hash, encoding);
                if (res != null) {
                    return res;
                }
            }
            res = new X509CRLImpl(encoding);
            CRL_CACHE.put(hash, encoding, res);
            return res;
        }
    }

    private static CRL getCRL(InputStream inStream) throws CRLException, IOException {
        CRL res;
        synchronized (CRL_CACHE) {
            inStream.mark(CRL_CACHE_SEED_LENGTH);
            byte[] buff = readBytes(inStream, CRL_CACHE_SEED_LENGTH);
            inStream.reset();
            if (buff == null) {
                throw new CRLException(Messages.getString("security.152"));
            }
            long hash = CRL_CACHE.getHash(buff);
            if (CRL_CACHE.contains(hash)) {
                byte[] encoding = new byte[BerInputStream.getLength(buff)];
                if (encoding.length < CRL_CACHE_SEED_LENGTH) {
                    throw new CRLException(Messages.getString("security.15B4"));
                }
                inStream.read(encoding);
                res = (CRL) CRL_CACHE.get(hash, encoding);
                if (res != null) {
                } else {
                    res = new X509CRLImpl(encoding);
                    CRL_CACHE.put(hash, encoding, res);
                }
            } else {
                res = new X509CRLImpl(inStream);
                CRL_CACHE.put(hash, res.getEncoded(), res);
            }
        }
        return res;
    }

    public static byte[] decode(byte[] in, int len) {
        int length = (len / 4) * 3;
        if (length == 0) {
            return new byte[0];
        }
        int out_index;
        byte[] result;
        byte[] out = new byte[length];
        int pad = 0;
        while (true) {
            byte chr = in[len - 1];
            if (!(chr == (byte) 10 || chr == (byte) 13 || chr == (byte) 32 || chr == (byte) 9)) {
                if (chr != (byte) 61) {
                    break;
                }
                pad++;
            }
            len--;
        }
        int in_index = 0;
        int quantum = 0;
        int i = 0;
        int out_index2 = 0;
        while (i < len) {
            chr = in[i];
            if (chr == (byte) 10 || chr == (byte) 13 || chr == (byte) 32) {
                out_index = out_index2;
            } else if (chr == (byte) 9) {
                out_index = out_index2;
            } else {
                int bits;
                if (chr >= (byte) 65 && chr <= (byte) 90) {
                    bits = chr - 65;
                } else if (chr >= (byte) 97 && chr <= (byte) 122) {
                    bits = chr - 71;
                } else if (chr >= (byte) 48 && chr <= (byte) 57) {
                    bits = chr + 4;
                } else if (chr == (byte) 43) {
                    bits = 62;
                } else if (chr != (byte) 47) {
                    return null;
                } else {
                    bits = 63;
                }
                quantum = (quantum << 6) | ((byte) bits);
                if (in_index % 4 == 3) {
                    out_index = out_index2 + 1;
                    out[out_index2] = (byte) ((16711680 & quantum) >> 16);
                    out_index2 = out_index + 1;
                    out[out_index] = (byte) ((65280 & quantum) >> 8);
                    out_index = out_index2 + 1;
                    out[out_index2] = (byte) (quantum & 255);
                } else {
                    out_index = out_index2;
                }
                in_index++;
            }
            i++;
            out_index2 = out_index;
        }
        if (pad > 0) {
            quantum <<= pad * 6;
            out_index = out_index2 + 1;
            out[out_index2] = (byte) ((16711680 & quantum) >> 16);
            if (pad == 1) {
                out_index2 = out_index + 1;
                out[out_index] = (byte) ((65280 & quantum) >> 8);
            }
            result = new byte[out_index];
            System.arraycopy(out, 0, result, 0, out_index);
            return result;
        }
        out_index = out_index2;
        result = new byte[out_index];
        System.arraycopy(out, 0, result, 0, out_index);
        return result;
    }
}

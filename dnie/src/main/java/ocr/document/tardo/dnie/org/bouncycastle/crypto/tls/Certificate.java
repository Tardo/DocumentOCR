package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

public class Certificate {
    public static final Certificate EMPTY_CHAIN = new Certificate(new org.bouncycastle.asn1.x509.Certificate[0]);
    protected org.bouncycastle.asn1.x509.Certificate[] certificateList;

    public Certificate(org.bouncycastle.asn1.x509.Certificate[] certificateArr) {
        if (certificateArr == null) {
            throw new IllegalArgumentException("'certificateList' cannot be null");
        }
        this.certificateList = certificateArr;
    }

    private org.bouncycastle.asn1.x509.Certificate[] clone(org.bouncycastle.asn1.x509.Certificate[] certificateArr) {
        Object obj = new org.bouncycastle.asn1.x509.Certificate[certificateArr.length];
        System.arraycopy(certificateArr, 0, obj, 0, obj.length);
        return obj;
    }

    public static Certificate parse(InputStream inputStream) throws IOException {
        int readUint24 = TlsUtils.readUint24(inputStream);
        if (readUint24 == 0) {
            return EMPTY_CHAIN;
        }
        Vector vector = new Vector();
        while (readUint24 > 0) {
            int readUint242 = TlsUtils.readUint24(inputStream);
            readUint24 -= readUint242 + 3;
            InputStream byteArrayInputStream = new ByteArrayInputStream(TlsUtils.readFully(readUint242, inputStream));
            ASN1Primitive readObject = new ASN1InputStream(byteArrayInputStream).readObject();
            TlsProtocol.assertEmpty(byteArrayInputStream);
            vector.addElement(org.bouncycastle.asn1.x509.Certificate.getInstance(readObject));
        }
        org.bouncycastle.asn1.x509.Certificate[] certificateArr = new org.bouncycastle.asn1.x509.Certificate[vector.size()];
        for (readUint242 = 0; readUint242 < vector.size(); readUint242++) {
            certificateArr[readUint242] = (org.bouncycastle.asn1.x509.Certificate) vector.elementAt(readUint242);
        }
        return new Certificate(certificateArr);
    }

    public void encode(OutputStream outputStream) throws IOException {
        int i = 0;
        Vector vector = new Vector(this.certificateList.length);
        int i2 = 0;
        for (org.bouncycastle.asn1.x509.Certificate encoded : this.certificateList) {
            Object encoded2 = encoded.getEncoded("DER");
            vector.addElement(encoded2);
            i2 += encoded2.length + 3;
        }
        TlsUtils.writeUint24(i2, outputStream);
        while (i < vector.size()) {
            TlsUtils.writeOpaque24((byte[]) vector.elementAt(i), outputStream);
            i++;
        }
    }

    public org.bouncycastle.asn1.x509.Certificate getCertificateAt(int i) {
        return this.certificateList[i];
    }

    public org.bouncycastle.asn1.x509.Certificate[] getCertificateList() {
        return clone(this.certificateList);
    }

    public org.bouncycastle.asn1.x509.Certificate[] getCerts() {
        return clone(this.certificateList);
    }

    public int getLength() {
        return this.certificateList.length;
    }

    public boolean isEmpty() {
        return this.certificateList.length == 0;
    }
}

package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;

public class CertificateRequest {
    private Vector certificateAuthorities;
    private short[] certificateTypes;

    public CertificateRequest(short[] sArr, Vector vector) {
        this.certificateTypes = sArr;
        this.certificateAuthorities = vector;
    }

    public static CertificateRequest parse(InputStream inputStream) throws IOException {
        short readUint8 = TlsUtils.readUint8(inputStream);
        short[] sArr = new short[readUint8];
        for (short s = (short) 0; s < readUint8; s++) {
            sArr[s] = TlsUtils.readUint8(inputStream);
        }
        byte[] readOpaque16 = TlsUtils.readOpaque16(inputStream);
        Vector vector = new Vector();
        InputStream byteArrayInputStream = new ByteArrayInputStream(readOpaque16);
        while (byteArrayInputStream.available() > 0) {
            vector.addElement(X500Name.getInstance(ASN1Primitive.fromByteArray(TlsUtils.readOpaque16(byteArrayInputStream))));
        }
        return new CertificateRequest(sArr, vector);
    }

    public void encode(OutputStream outputStream) throws IOException {
        int i = 0;
        if (this.certificateTypes == null || this.certificateTypes.length == 0) {
            TlsUtils.writeUint8((short) 0, outputStream);
        } else {
            TlsUtils.writeUint8((short) this.certificateTypes.length, outputStream);
            TlsUtils.writeUint8Array(this.certificateTypes, outputStream);
        }
        if (this.certificateAuthorities == null || this.certificateAuthorities.isEmpty()) {
            TlsUtils.writeUint16(0, outputStream);
            return;
        }
        Vector vector = new Vector(this.certificateAuthorities.size());
        int i2 = 0;
        for (int i3 = 0; i3 < this.certificateAuthorities.size(); i3++) {
            Object encoded = ((X500Name) this.certificateAuthorities.elementAt(i3)).getEncoded("DER");
            vector.addElement(encoded);
            i2 += encoded.length;
        }
        TlsUtils.writeUint16(i2, outputStream);
        while (i < vector.size()) {
            outputStream.write((byte[]) vector.elementAt(i));
            i++;
        }
    }

    public Vector getCertificateAuthorities() {
        return this.certificateAuthorities;
    }

    public short[] getCertificateTypes() {
        return this.certificateTypes;
    }
}

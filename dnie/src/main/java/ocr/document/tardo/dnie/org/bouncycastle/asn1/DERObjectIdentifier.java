package org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.util.Arrays;

public class DERObjectIdentifier extends ASN1Primitive {
    private static final long LONG_LIMIT = 72057594037927808L;
    private static ASN1ObjectIdentifier[][] cache = new ASN1ObjectIdentifier[256][];
    private byte[] body;
    String identifier;

    public DERObjectIdentifier(String str) {
        if (str == null) {
            throw new IllegalArgumentException("'identifier' cannot be null");
        } else if (isValidIdentifier(str)) {
            this.identifier = str;
        } else {
            throw new IllegalArgumentException("string " + str + " not an OID");
        }
    }

    DERObjectIdentifier(DERObjectIdentifier dERObjectIdentifier, String str) {
        if (isValidBranchID(str, 0)) {
            this.identifier = dERObjectIdentifier.getId() + "." + str;
            return;
        }
        throw new IllegalArgumentException("string " + str + " not a valid OID branch");
    }

    DERObjectIdentifier(byte[] bArr) {
        StringBuffer stringBuffer = new StringBuffer();
        Object obj = 1;
        BigInteger bigInteger = null;
        long j = 0;
        for (int i = 0; i != bArr.length; i++) {
            int i2 = bArr[i] & 255;
            if (j <= LONG_LIMIT) {
                j += (long) (i2 & CertificateBody.profileType);
                if ((i2 & 128) == 0) {
                    if (obj != null) {
                        if (j < 40) {
                            stringBuffer.append('0');
                        } else if (j < 80) {
                            stringBuffer.append('1');
                            j -= 40;
                        } else {
                            stringBuffer.append('2');
                            j -= 80;
                        }
                        obj = null;
                    }
                    stringBuffer.append('.');
                    stringBuffer.append(j);
                    j = 0;
                } else {
                    j <<= 7;
                }
            } else {
                if (bigInteger == null) {
                    bigInteger = BigInteger.valueOf(j);
                }
                bigInteger = bigInteger.or(BigInteger.valueOf((long) (i2 & CertificateBody.profileType)));
                if ((i2 & 128) == 0) {
                    Object obj2;
                    Object obj3;
                    if (obj != null) {
                        stringBuffer.append('2');
                        obj = bigInteger.subtract(BigInteger.valueOf(80));
                        obj2 = null;
                    } else {
                        obj3 = obj;
                        BigInteger bigInteger2 = bigInteger;
                        obj2 = obj3;
                    }
                    stringBuffer.append('.');
                    stringBuffer.append(obj);
                    j = 0;
                    obj3 = obj2;
                    bigInteger = null;
                    obj = obj3;
                } else {
                    bigInteger = bigInteger.shiftLeft(7);
                }
            }
        }
        this.identifier = stringBuffer.toString();
        this.body = Arrays.clone(bArr);
    }

    private void doOutput(ByteArrayOutputStream byteArrayOutputStream) {
        OIDTokenizer oIDTokenizer = new OIDTokenizer(this.identifier);
        int parseInt = Integer.parseInt(oIDTokenizer.nextToken()) * 40;
        String nextToken = oIDTokenizer.nextToken();
        if (nextToken.length() <= 18) {
            writeField(byteArrayOutputStream, Long.parseLong(nextToken) + ((long) parseInt));
        } else {
            writeField(byteArrayOutputStream, new BigInteger(nextToken).add(BigInteger.valueOf((long) parseInt)));
        }
        while (oIDTokenizer.hasMoreTokens()) {
            String nextToken2 = oIDTokenizer.nextToken();
            if (nextToken2.length() <= 18) {
                writeField(byteArrayOutputStream, Long.parseLong(nextToken2));
            } else {
                writeField(byteArrayOutputStream, new BigInteger(nextToken2));
            }
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    static org.bouncycastle.asn1.ASN1ObjectIdentifier fromOctetString(byte[] r5) {
        /*
        r0 = r5.length;
        r1 = 3;
        if (r0 >= r1) goto L_0x000a;
    L_0x0004:
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier;
        r0.<init>(r5);
    L_0x0009:
        return r0;
    L_0x000a:
        r0 = r5.length;
        r0 = r0 + -2;
        r0 = r5[r0];
        r2 = r0 & 255;
        r0 = r5.length;
        r0 = r0 + -1;
        r0 = r5[r0];
        r3 = r0 & 127;
        r4 = cache;
        monitor-enter(r4);
        r0 = cache;	 Catch:{ all -> 0x0037 }
        r0 = r0[r2];	 Catch:{ all -> 0x0037 }
        if (r0 != 0) goto L_0x0097;
    L_0x0021:
        r1 = cache;	 Catch:{ all -> 0x0037 }
        r0 = 128; // 0x80 float:1.794E-43 double:6.32E-322;
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier[r0];	 Catch:{ all -> 0x0037 }
        r1[r2] = r0;	 Catch:{ all -> 0x0037 }
        r1 = r0;
    L_0x002a:
        r0 = r1[r3];	 Catch:{ all -> 0x0037 }
        if (r0 != 0) goto L_0x003a;
    L_0x002e:
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier;	 Catch:{ all -> 0x0037 }
        r0.<init>(r5);	 Catch:{ all -> 0x0037 }
        r1[r3] = r0;	 Catch:{ all -> 0x0037 }
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        goto L_0x0009;
    L_0x0037:
        r0 = move-exception;
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        throw r0;
    L_0x003a:
        r1 = r0.getBody();	 Catch:{ all -> 0x0037 }
        r1 = org.bouncycastle.util.Arrays.areEqual(r5, r1);	 Catch:{ all -> 0x0037 }
        if (r1 == 0) goto L_0x0046;
    L_0x0044:
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        goto L_0x0009;
    L_0x0046:
        r0 = r2 + 1;
        r1 = r0 & 255;
        r0 = cache;	 Catch:{ all -> 0x0037 }
        r0 = r0[r1];	 Catch:{ all -> 0x0037 }
        if (r0 != 0) goto L_0x0095;
    L_0x0050:
        r2 = cache;	 Catch:{ all -> 0x0037 }
        r0 = 128; // 0x80 float:1.794E-43 double:6.32E-322;
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier[r0];	 Catch:{ all -> 0x0037 }
        r2[r1] = r0;	 Catch:{ all -> 0x0037 }
        r1 = r0;
    L_0x0059:
        r0 = r1[r3];	 Catch:{ all -> 0x0037 }
        if (r0 != 0) goto L_0x0066;
    L_0x005d:
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier;	 Catch:{ all -> 0x0037 }
        r0.<init>(r5);	 Catch:{ all -> 0x0037 }
        r1[r3] = r0;	 Catch:{ all -> 0x0037 }
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        goto L_0x0009;
    L_0x0066:
        r2 = r0.getBody();	 Catch:{ all -> 0x0037 }
        r2 = org.bouncycastle.util.Arrays.areEqual(r5, r2);	 Catch:{ all -> 0x0037 }
        if (r2 == 0) goto L_0x0072;
    L_0x0070:
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        goto L_0x0009;
    L_0x0072:
        r0 = r3 + 1;
        r2 = r0 & 127;
        r0 = r1[r2];	 Catch:{ all -> 0x0037 }
        if (r0 != 0) goto L_0x0083;
    L_0x007a:
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier;	 Catch:{ all -> 0x0037 }
        r0.<init>(r5);	 Catch:{ all -> 0x0037 }
        r1[r2] = r0;	 Catch:{ all -> 0x0037 }
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        goto L_0x0009;
    L_0x0083:
        monitor-exit(r4);	 Catch:{ all -> 0x0037 }
        r1 = r0.getBody();
        r1 = org.bouncycastle.util.Arrays.areEqual(r5, r1);
        if (r1 != 0) goto L_0x0009;
    L_0x008e:
        r0 = new org.bouncycastle.asn1.ASN1ObjectIdentifier;
        r0.<init>(r5);
        goto L_0x0009;
    L_0x0095:
        r1 = r0;
        goto L_0x0059;
    L_0x0097:
        r1 = r0;
        goto L_0x002a;
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.asn1.DERObjectIdentifier.fromOctetString(byte[]):org.bouncycastle.asn1.ASN1ObjectIdentifier");
    }

    public static ASN1ObjectIdentifier getInstance(Object obj) {
        if (obj == null || (obj instanceof ASN1ObjectIdentifier)) {
            return (ASN1ObjectIdentifier) obj;
        }
        if (obj instanceof DERObjectIdentifier) {
            return new ASN1ObjectIdentifier(((DERObjectIdentifier) obj).getId());
        }
        if ((obj instanceof ASN1Encodable) && (((ASN1Encodable) obj).toASN1Primitive() instanceof ASN1ObjectIdentifier)) {
            return (ASN1ObjectIdentifier) ((ASN1Encodable) obj).toASN1Primitive();
        }
        if (obj instanceof byte[]) {
            return fromOctetString((byte[]) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        ASN1Primitive object = aSN1TaggedObject.getObject();
        return (z || (object instanceof DERObjectIdentifier)) ? getInstance(object) : fromOctetString(ASN1OctetString.getInstance(aSN1TaggedObject.getObject()).getOctets());
    }

    private static boolean isValidBranchID(String str, int i) {
        int length = str.length();
        boolean z = false;
        while (true) {
            length--;
            if (length < i) {
                return z;
            }
            char charAt = str.charAt(length);
            if ('0' <= charAt && charAt <= '9') {
                z = true;
            } else if (charAt != '.' || !z) {
                return false;
            } else {
                z = false;
            }
        }
    }

    private static boolean isValidIdentifier(String str) {
        if (str.length() < 3 || str.charAt(1) != '.') {
            return false;
        }
        char charAt = str.charAt(0);
        return (charAt < '0' || charAt > '2') ? false : isValidBranchID(str, 2);
    }

    private void writeField(ByteArrayOutputStream byteArrayOutputStream, long j) {
        byte[] bArr = new byte[9];
        int i = 8;
        bArr[8] = (byte) (((int) j) & CertificateBody.profileType);
        while (j >= 128) {
            j >>= 7;
            i--;
            bArr[i] = (byte) ((((int) j) & CertificateBody.profileType) | 128);
        }
        byteArrayOutputStream.write(bArr, i, 9 - i);
    }

    private void writeField(ByteArrayOutputStream byteArrayOutputStream, BigInteger bigInteger) {
        int bitLength = (bigInteger.bitLength() + 6) / 7;
        if (bitLength == 0) {
            byteArrayOutputStream.write(0);
            return;
        }
        int i;
        byte[] bArr = new byte[bitLength];
        for (i = bitLength - 1; i >= 0; i--) {
            bArr[i] = (byte) ((bigInteger.intValue() & CertificateBody.profileType) | 128);
            bigInteger = bigInteger.shiftRight(7);
        }
        i = bitLength - 1;
        bArr[i] = (byte) (bArr[i] & CertificateBody.profileType);
        byteArrayOutputStream.write(bArr, 0, bArr.length);
    }

    boolean asn1Equals(ASN1Primitive aSN1Primitive) {
        return !(aSN1Primitive instanceof DERObjectIdentifier) ? false : this.identifier.equals(((DERObjectIdentifier) aSN1Primitive).identifier);
    }

    void encode(ASN1OutputStream aSN1OutputStream) throws IOException {
        byte[] body = getBody();
        aSN1OutputStream.write(6);
        aSN1OutputStream.writeLength(body.length);
        aSN1OutputStream.write(body);
    }

    int encodedLength() throws IOException {
        int length = getBody().length;
        return length + (StreamUtil.calculateBodyLength(length) + 1);
    }

    protected synchronized byte[] getBody() {
        if (this.body == null) {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            doOutput(byteArrayOutputStream);
            this.body = byteArrayOutputStream.toByteArray();
        }
        return this.body;
    }

    public String getId() {
        return this.identifier;
    }

    public int hashCode() {
        return this.identifier.hashCode();
    }

    boolean isConstructed() {
        return false;
    }

    public String toString() {
        return getId();
    }
}

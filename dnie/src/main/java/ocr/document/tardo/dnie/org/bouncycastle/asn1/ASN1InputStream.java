package org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.util.io.Streams;

public class ASN1InputStream extends FilterInputStream implements BERTags {
    private final boolean lazyEvaluate;
    private final int limit;
    private final byte[][] tmpBuffers;

    public ASN1InputStream(InputStream inputStream) {
        this(inputStream, StreamUtil.findLimit(inputStream));
    }

    public ASN1InputStream(InputStream inputStream, int i) {
        this(inputStream, i, false);
    }

    public ASN1InputStream(InputStream inputStream, int i, boolean z) {
        super(inputStream);
        this.limit = i;
        this.lazyEvaluate = z;
        this.tmpBuffers = new byte[11][];
    }

    public ASN1InputStream(InputStream inputStream, boolean z) {
        this(inputStream, StreamUtil.findLimit(inputStream), z);
    }

    public ASN1InputStream(byte[] bArr) {
        this(new ByteArrayInputStream(bArr), bArr.length);
    }

    public ASN1InputStream(byte[] bArr, boolean z) {
        this(new ByteArrayInputStream(bArr), bArr.length, z);
    }

    static ASN1Primitive createPrimitiveDERObject(int i, DefiniteLengthInputStream definiteLengthInputStream, byte[][] bArr) throws IOException {
        switch (i) {
            case 1:
                return DERBoolean.fromOctetString(getBuffer(definiteLengthInputStream, bArr));
            case 2:
                return new ASN1Integer(definiteLengthInputStream.toByteArray());
            case 3:
                return DERBitString.fromInputStream(definiteLengthInputStream.getRemaining(), definiteLengthInputStream);
            case 4:
                return new DEROctetString(definiteLengthInputStream.toByteArray());
            case 5:
                return DERNull.INSTANCE;
            case 6:
                return DERObjectIdentifier.fromOctetString(getBuffer(definiteLengthInputStream, bArr));
            case 10:
                return DEREnumerated.fromOctetString(getBuffer(definiteLengthInputStream, bArr));
            case 12:
                return new DERUTF8String(definiteLengthInputStream.toByteArray());
            case 18:
                return new DERNumericString(definiteLengthInputStream.toByteArray());
            case 19:
                return new DERPrintableString(definiteLengthInputStream.toByteArray());
            case 20:
                return new DERT61String(definiteLengthInputStream.toByteArray());
            case 22:
                return new DERIA5String(definiteLengthInputStream.toByteArray());
            case 23:
                return new ASN1UTCTime(definiteLengthInputStream.toByteArray());
            case 24:
                return new ASN1GeneralizedTime(definiteLengthInputStream.toByteArray());
            case 26:
                return new DERVisibleString(definiteLengthInputStream.toByteArray());
            case 27:
                return new DERGeneralString(definiteLengthInputStream.toByteArray());
            case 28:
                return new DERUniversalString(definiteLengthInputStream.toByteArray());
            case 30:
                return new DERBMPString(getBMPCharBuffer(definiteLengthInputStream));
            default:
                throw new IOException("unknown tag " + i + " encountered");
        }
    }

    private static char[] getBMPCharBuffer(DefiniteLengthInputStream definiteLengthInputStream) throws IOException {
        int remaining = definiteLengthInputStream.getRemaining() / 2;
        char[] cArr = new char[remaining];
        int i = 0;
        while (i < remaining) {
            int read = definiteLengthInputStream.read();
            if (read >= 0) {
                int read2 = definiteLengthInputStream.read();
                if (read2 < 0) {
                    break;
                }
                int i2 = i + 1;
                cArr[i] = (char) ((read << 8) | (read2 & 255));
                i = i2;
            } else {
                break;
            }
        }
        return cArr;
    }

    private static byte[] getBuffer(DefiniteLengthInputStream definiteLengthInputStream, byte[][] bArr) throws IOException {
        int remaining = definiteLengthInputStream.getRemaining();
        if (definiteLengthInputStream.getRemaining() >= bArr.length) {
            return definiteLengthInputStream.toByteArray();
        }
        byte[] bArr2 = bArr[remaining];
        if (bArr2 == null) {
            bArr2 = new byte[remaining];
            bArr[remaining] = bArr2;
        }
        Streams.readFully(definiteLengthInputStream, bArr2);
        return bArr2;
    }

    static int readLength(InputStream inputStream, int i) throws IOException {
        int i2 = 0;
        int read = inputStream.read();
        if (read < 0) {
            throw new EOFException("EOF found when length expected");
        } else if (read == 128) {
            return -1;
        } else {
            if (read <= CertificateBody.profileType) {
                return read;
            }
            int i3 = read & CertificateBody.profileType;
            if (i3 > 4) {
                throw new IOException("DER length more than 4 bytes: " + i3);
            }
            read = 0;
            while (i2 < i3) {
                int read2 = inputStream.read();
                if (read2 < 0) {
                    throw new EOFException("EOF found reading length");
                }
                i2++;
                read = read2 + (read << 8);
            }
            if (read < 0) {
                throw new IOException("corrupted stream - negative length found");
            } else if (read < i) {
                return read;
            } else {
                throw new IOException("corrupted stream - out of bounds length found");
            }
        }
    }

    static int readTagNumber(InputStream inputStream, int i) throws IOException {
        int i2 = i & 31;
        if (i2 != 31) {
            return i2;
        }
        int i3 = 0;
        i2 = inputStream.read();
        if ((i2 & CertificateBody.profileType) == 0) {
            throw new IOException("corrupted stream - invalid high tag number found");
        }
        while (i2 >= 0 && (i2 & 128) != 0) {
            i3 = ((i2 & CertificateBody.profileType) | i3) << 7;
            i2 = inputStream.read();
        }
        if (i2 >= 0) {
            return (i2 & CertificateBody.profileType) | i3;
        }
        throw new EOFException("EOF found inside tag value.");
    }

    ASN1EncodableVector buildDEREncodableVector(DefiniteLengthInputStream definiteLengthInputStream) throws IOException {
        return new ASN1InputStream((InputStream) definiteLengthInputStream).buildEncodableVector();
    }

    ASN1EncodableVector buildEncodableVector() throws IOException {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        while (true) {
            ASN1Encodable readObject = readObject();
            if (readObject == null) {
                return aSN1EncodableVector;
            }
            aSN1EncodableVector.add(readObject);
        }
    }

    protected ASN1Primitive buildObject(int i, int i2, int i3) throws IOException {
        int i4 = 0;
        boolean z = (i & 32) != 0;
        InputStream definiteLengthInputStream = new DefiniteLengthInputStream(this, i3);
        if ((i & 64) != 0) {
            return new DERApplicationSpecific(z, i2, definiteLengthInputStream.toByteArray());
        }
        if ((i & 128) != 0) {
            return new ASN1StreamParser(definiteLengthInputStream).readTaggedObject(z, i2);
        }
        if (!z) {
            return createPrimitiveDERObject(i2, definiteLengthInputStream, this.tmpBuffers);
        }
        switch (i2) {
            case 4:
                ASN1EncodableVector buildDEREncodableVector = buildDEREncodableVector(definiteLengthInputStream);
                ASN1OctetString[] aSN1OctetStringArr = new ASN1OctetString[buildDEREncodableVector.size()];
                while (i4 != aSN1OctetStringArr.length) {
                    aSN1OctetStringArr[i4] = (ASN1OctetString) buildDEREncodableVector.get(i4);
                    i4++;
                }
                return new BEROctetString(aSN1OctetStringArr);
            case 8:
                return new DERExternal(buildDEREncodableVector(definiteLengthInputStream));
            case 16:
                return this.lazyEvaluate ? new LazyEncodedSequence(definiteLengthInputStream.toByteArray()) : DERFactory.createSequence(buildDEREncodableVector(definiteLengthInputStream));
            case 17:
                return DERFactory.createSet(buildDEREncodableVector(definiteLengthInputStream));
            default:
                throw new IOException("unknown tag " + i2 + " encountered");
        }
    }

    int getLimit() {
        return this.limit;
    }

    protected void readFully(byte[] bArr) throws IOException {
        if (Streams.readFully(this, bArr) != bArr.length) {
            throw new EOFException("EOF encountered in middle of object");
        }
    }

    protected int readLength() throws IOException {
        return readLength(this, this.limit);
    }

    public ASN1Primitive readObject() throws IOException {
        int read = read();
        if (read > 0) {
            int readTagNumber = readTagNumber(this, read);
            boolean z = (read & 32) != 0;
            int readLength = readLength();
            if (readLength >= 0) {
                try {
                    return buildObject(read, readTagNumber, readLength);
                } catch (Throwable e) {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
            } else if (z) {
                ASN1StreamParser aSN1StreamParser = new ASN1StreamParser(new IndefiniteLengthInputStream(this, this.limit), this.limit);
                if ((read & 64) != 0) {
                    return new BERApplicationSpecificParser(readTagNumber, aSN1StreamParser).getLoadedObject();
                }
                if ((read & 128) != 0) {
                    return new BERTaggedObjectParser(true, readTagNumber, aSN1StreamParser).getLoadedObject();
                }
                switch (readTagNumber) {
                    case 4:
                        return new BEROctetStringParser(aSN1StreamParser).getLoadedObject();
                    case 8:
                        return new DERExternalParser(aSN1StreamParser).getLoadedObject();
                    case 16:
                        return new BERSequenceParser(aSN1StreamParser).getLoadedObject();
                    case 17:
                        return new BERSetParser(aSN1StreamParser).getLoadedObject();
                    default:
                        throw new IOException("unknown BER object encountered");
                }
            } else {
                throw new IOException("indefinite length primitive encoding encountered");
            }
        } else if (read != 0) {
            return null;
        } else {
            throw new IOException("unexpected end-of-contents marker");
        }
    }
}

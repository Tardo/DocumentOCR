package org.spongycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.spongycastle.util.io.Streams;

public class ASN1InputStream extends FilterInputStream implements DERTags {
    private final boolean lazyEvaluate;
    private final int limit;

    static int findLimit(InputStream in) {
        if (in instanceof LimitedInputStream) {
            return ((LimitedInputStream) in).getRemaining();
        }
        if (in instanceof ByteArrayInputStream) {
            return ((ByteArrayInputStream) in).available();
        }
        return Integer.MAX_VALUE;
    }

    public ASN1InputStream(InputStream is) {
        this(is, findLimit(is));
    }

    public ASN1InputStream(byte[] input) {
        this(new ByteArrayInputStream(input), input.length);
    }

    public ASN1InputStream(byte[] input, boolean lazyEvaluate) {
        this(new ByteArrayInputStream(input), input.length, lazyEvaluate);
    }

    public ASN1InputStream(InputStream input, int limit) {
        this(input, limit, false);
    }

    public ASN1InputStream(InputStream input, int limit, boolean lazyEvaluate) {
        super(input);
        this.limit = limit;
        this.lazyEvaluate = lazyEvaluate;
    }

    protected int readLength() throws IOException {
        return readLength(this, this.limit);
    }

    protected void readFully(byte[] bytes) throws IOException {
        if (Streams.readFully(this, bytes) != bytes.length) {
            throw new EOFException("EOF encountered in middle of object");
        }
    }

    protected DERObject buildObject(int tag, int tagNo, int length) throws IOException {
        boolean isConstructed;
        if ((tag & 32) != 0) {
            isConstructed = true;
        } else {
            isConstructed = false;
        }
        InputStream defIn = new DefiniteLengthInputStream(this, length);
        if ((tag & 64) != 0) {
            return new DERApplicationSpecific(isConstructed, tagNo, defIn.toByteArray());
        }
        if ((tag & 128) != 0) {
            return new ASN1StreamParser(defIn).readTaggedObject(isConstructed, tagNo);
        }
        if (!isConstructed) {
            return createPrimitiveDERObject(tagNo, defIn.toByteArray());
        }
        switch (tagNo) {
            case 4:
                return new BERConstructedOctetString(buildDEREncodableVector(defIn).f347v);
            case 8:
                return new DERExternal(buildDEREncodableVector(defIn));
            case 16:
                if (this.lazyEvaluate) {
                    return new LazyDERSequence(defIn.toByteArray());
                }
                return DERFactory.createSequence(buildDEREncodableVector(defIn));
            case 17:
                return DERFactory.createSet(buildDEREncodableVector(defIn), false);
            default:
                return new DERUnknownTag(true, tagNo, defIn.toByteArray());
        }
    }

    ASN1EncodableVector buildEncodableVector() throws IOException {
        ASN1EncodableVector v = new ASN1EncodableVector();
        while (true) {
            DERObject o = readObject();
            if (o == null) {
                return v;
            }
            v.add(o);
        }
    }

    ASN1EncodableVector buildDEREncodableVector(DefiniteLengthInputStream dIn) throws IOException {
        return new ASN1InputStream((InputStream) dIn).buildEncodableVector();
    }

    public DERObject readObject() throws IOException {
        int tag = read();
        if (tag > 0) {
            int tagNo = readTagNumber(this, tag);
            boolean isConstructed = (tag & 32) != 0;
            int length = readLength();
            if (length >= 0) {
                try {
                    return buildObject(tag, tagNo, length);
                } catch (IllegalArgumentException e) {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
            } else if (isConstructed) {
                ASN1StreamParser sp = new ASN1StreamParser(new IndefiniteLengthInputStream(this, this.limit), this.limit);
                if ((tag & 64) != 0) {
                    return new BERApplicationSpecificParser(tagNo, sp).getLoadedObject();
                }
                if ((tag & 128) != 0) {
                    return new BERTaggedObjectParser(true, tagNo, sp).getLoadedObject();
                }
                switch (tagNo) {
                    case 4:
                        return new BEROctetStringParser(sp).getLoadedObject();
                    case 8:
                        return new DERExternalParser(sp).getLoadedObject();
                    case 16:
                        return new BERSequenceParser(sp).getLoadedObject();
                    case 17:
                        return new BERSetParser(sp).getLoadedObject();
                    default:
                        throw new IOException("unknown BER object encountered");
                }
            } else {
                throw new IOException("indefinite length primitive encoding encountered");
            }
        } else if (tag != 0) {
            return null;
        } else {
            throw new IOException("unexpected end-of-contents marker");
        }
    }

    static int readTagNumber(InputStream s, int tag) throws IOException {
        int tagNo = tag & 31;
        if (tagNo != 31) {
            return tagNo;
        }
        tagNo = 0;
        int b = s.read();
        if ((b & CertificateBody.profileType) == 0) {
            throw new IOException("corrupted stream - invalid high tag number found");
        }
        while (b >= 0 && (b & 128) != 0) {
            tagNo = (tagNo | (b & CertificateBody.profileType)) << 7;
            b = s.read();
        }
        if (b >= 0) {
            return tagNo | (b & CertificateBody.profileType);
        }
        throw new EOFException("EOF found inside tag value.");
    }

    static int readLength(InputStream s, int limit) throws IOException {
        int length = s.read();
        if (length < 0) {
            throw new EOFException("EOF found when length expected");
        } else if (length == 128) {
            return -1;
        } else {
            if (length > CertificateBody.profileType) {
                int size = length & CertificateBody.profileType;
                if (size > 4) {
                    throw new IOException("DER length more than 4 bytes: " + size);
                }
                length = 0;
                for (int i = 0; i < size; i++) {
                    int next = s.read();
                    if (next < 0) {
                        throw new EOFException("EOF found reading length");
                    }
                    length = (length << 8) + next;
                }
                if (length < 0) {
                    throw new IOException("corrupted stream - negative length found");
                } else if (length >= limit) {
                    throw new IOException("corrupted stream - out of bounds length found");
                }
            }
            return length;
        }
    }

    static DERObject createPrimitiveDERObject(int tagNo, byte[] bytes) {
        switch (tagNo) {
            case 1:
                return new ASN1Boolean(bytes);
            case 2:
                return new ASN1Integer(bytes);
            case 3:
                return DERBitString.fromOctetString(bytes);
            case 4:
                return new DEROctetString(bytes);
            case 5:
                return DERNull.INSTANCE;
            case 6:
                return new ASN1ObjectIdentifier(bytes);
            case 10:
                return new ASN1Enumerated(bytes);
            case 12:
                return new DERUTF8String(bytes);
            case 18:
                return new DERNumericString(bytes);
            case 19:
                return new DERPrintableString(bytes);
            case 20:
                return new DERT61String(bytes);
            case 22:
                return new DERIA5String(bytes);
            case 23:
                return new ASN1UTCTime(bytes);
            case 24:
                return new ASN1GeneralizedTime(bytes);
            case 26:
                return new DERVisibleString(bytes);
            case 27:
                return new DERGeneralString(bytes);
            case 28:
                return new DERUniversalString(bytes);
            case 30:
                return new DERBMPString(bytes);
            default:
                return new DERUnknownTag(false, tagNo, bytes);
        }
    }
}

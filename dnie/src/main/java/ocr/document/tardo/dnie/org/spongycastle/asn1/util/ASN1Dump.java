package org.spongycastle.asn1.util;

import java.io.IOException;
import java.util.Enumeration;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.BERApplicationSpecific;
import org.spongycastle.asn1.BERConstructedOctetString;
import org.spongycastle.asn1.BERSequence;
import org.spongycastle.asn1.BERSet;
import org.spongycastle.asn1.BERTaggedObject;
import org.spongycastle.asn1.DERApplicationSpecific;
import org.spongycastle.asn1.DERBMPString;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DERBoolean;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DEREnumerated;
import org.spongycastle.asn1.DERExternal;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERNull;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.DERT61String;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.DERUTCTime;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.DERUnknownTag;
import org.spongycastle.asn1.DERVisibleString;
import org.spongycastle.util.encoders.Hex;

public class ASN1Dump {
    private static final int SAMPLE_SIZE = 32;
    private static final String TAB = "    ";

    static void _dumpAsString(String indent, boolean verbose, DERObject obj, StringBuffer buf) {
        String nl = System.getProperty("line.separator");
        Enumeration e;
        String tab;
        Object o;
        if (obj instanceof ASN1Sequence) {
            e = ((ASN1Sequence) obj).getObjects();
            tab = indent + TAB;
            buf.append(indent);
            if (obj instanceof BERSequence) {
                buf.append("BER Sequence");
            } else if (obj instanceof DERSequence) {
                buf.append("DER Sequence");
            } else {
                buf.append("Sequence");
            }
            buf.append(nl);
            while (e.hasMoreElements()) {
                o = e.nextElement();
                if (o == null || o.equals(new DERNull())) {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                } else if (o instanceof DERObject) {
                    _dumpAsString(tab, verbose, (DERObject) o, buf);
                } else {
                    _dumpAsString(tab, verbose, ((DEREncodable) o).getDERObject(), buf);
                }
            }
        } else if (obj instanceof DERTaggedObject) {
            tab = indent + TAB;
            buf.append(indent);
            if (obj instanceof BERTaggedObject) {
                buf.append("BER Tagged [");
            } else {
                buf.append("Tagged [");
            }
            DERTaggedObject o2 = (DERTaggedObject) obj;
            buf.append(Integer.toString(o2.getTagNo()));
            buf.append(']');
            if (!o2.isExplicit()) {
                buf.append(" IMPLICIT ");
            }
            buf.append(nl);
            if (o2.isEmpty()) {
                buf.append(tab);
                buf.append("EMPTY");
                buf.append(nl);
                return;
            }
            _dumpAsString(tab, verbose, o2.getObject(), buf);
        } else if (obj instanceof BERSet) {
            e = ((ASN1Set) obj).getObjects();
            tab = indent + TAB;
            buf.append(indent);
            buf.append("BER Set");
            buf.append(nl);
            while (e.hasMoreElements()) {
                o = e.nextElement();
                if (o == null) {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                } else if (o instanceof DERObject) {
                    _dumpAsString(tab, verbose, (DERObject) o, buf);
                } else {
                    _dumpAsString(tab, verbose, ((DEREncodable) o).getDERObject(), buf);
                }
            }
        } else if (obj instanceof DERSet) {
            e = ((ASN1Set) obj).getObjects();
            tab = indent + TAB;
            buf.append(indent);
            buf.append("DER Set");
            buf.append(nl);
            while (e.hasMoreElements()) {
                o = e.nextElement();
                if (o == null) {
                    buf.append(tab);
                    buf.append("NULL");
                    buf.append(nl);
                } else if (o instanceof DERObject) {
                    _dumpAsString(tab, verbose, (DERObject) o, buf);
                } else {
                    _dumpAsString(tab, verbose, ((DEREncodable) o).getDERObject(), buf);
                }
            }
        } else if (obj instanceof DERObjectIdentifier) {
            buf.append(indent + "ObjectIdentifier(" + ((DERObjectIdentifier) obj).getId() + ")" + nl);
        } else if (obj instanceof DERBoolean) {
            buf.append(indent + "Boolean(" + ((DERBoolean) obj).isTrue() + ")" + nl);
        } else if (obj instanceof DERInteger) {
            buf.append(indent + "Integer(" + ((DERInteger) obj).getValue() + ")" + nl);
        } else if (obj instanceof BERConstructedOctetString) {
            oct = (ASN1OctetString) obj;
            buf.append(indent + "BER Constructed Octet String" + "[" + oct.getOctets().length + "] ");
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, oct.getOctets()));
            } else {
                buf.append(nl);
            }
        } else if (obj instanceof DEROctetString) {
            oct = (ASN1OctetString) obj;
            buf.append(indent + "DER Octet String" + "[" + oct.getOctets().length + "] ");
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, oct.getOctets()));
            } else {
                buf.append(nl);
            }
        } else if (obj instanceof DERBitString) {
            DERBitString bt = (DERBitString) obj;
            buf.append(indent + "DER Bit String" + "[" + bt.getBytes().length + ", " + bt.getPadBits() + "] ");
            if (verbose) {
                buf.append(dumpBinaryDataAsString(indent, bt.getBytes()));
            } else {
                buf.append(nl);
            }
        } else if (obj instanceof DERIA5String) {
            buf.append(indent + "IA5String(" + ((DERIA5String) obj).getString() + ") " + nl);
        } else if (obj instanceof DERUTF8String) {
            buf.append(indent + "UTF8String(" + ((DERUTF8String) obj).getString() + ") " + nl);
        } else if (obj instanceof DERPrintableString) {
            buf.append(indent + "PrintableString(" + ((DERPrintableString) obj).getString() + ") " + nl);
        } else if (obj instanceof DERVisibleString) {
            buf.append(indent + "VisibleString(" + ((DERVisibleString) obj).getString() + ") " + nl);
        } else if (obj instanceof DERBMPString) {
            buf.append(indent + "BMPString(" + ((DERBMPString) obj).getString() + ") " + nl);
        } else if (obj instanceof DERT61String) {
            buf.append(indent + "T61String(" + ((DERT61String) obj).getString() + ") " + nl);
        } else if (obj instanceof DERUTCTime) {
            buf.append(indent + "UTCTime(" + ((DERUTCTime) obj).getTime() + ") " + nl);
        } else if (obj instanceof DERGeneralizedTime) {
            buf.append(indent + "GeneralizedTime(" + ((DERGeneralizedTime) obj).getTime() + ") " + nl);
        } else if (obj instanceof DERUnknownTag) {
            buf.append(indent + "Unknown " + Integer.toString(((DERUnknownTag) obj).getTag(), 16) + " " + new String(Hex.encode(((DERUnknownTag) obj).getData())) + nl);
        } else if (obj instanceof BERApplicationSpecific) {
            buf.append(outputApplicationSpecific("BER", indent, verbose, obj, nl));
        } else if (obj instanceof DERApplicationSpecific) {
            buf.append(outputApplicationSpecific("DER", indent, verbose, obj, nl));
        } else if (obj instanceof DEREnumerated) {
            buf.append(indent + "DER Enumerated(" + ((DEREnumerated) obj).getValue() + ")" + nl);
        } else if (obj instanceof DERExternal) {
            DERExternal ext = (DERExternal) obj;
            buf.append(indent + "External " + nl);
            tab = indent + TAB;
            if (ext.getDirectReference() != null) {
                buf.append(tab + "Direct Reference: " + ext.getDirectReference().getId() + nl);
            }
            if (ext.getIndirectReference() != null) {
                buf.append(tab + "Indirect Reference: " + ext.getIndirectReference().toString() + nl);
            }
            if (ext.getDataValueDescriptor() != null) {
                _dumpAsString(tab, verbose, ext.getDataValueDescriptor(), buf);
            }
            buf.append(tab + "Encoding: " + ext.getEncoding() + nl);
            _dumpAsString(tab, verbose, ext.getExternalContent(), buf);
        } else {
            buf.append(indent + obj.toString() + nl);
        }
    }

    private static String outputApplicationSpecific(String type, String indent, boolean verbose, DERObject obj, String nl) {
        DERApplicationSpecific app = (DERApplicationSpecific) obj;
        StringBuffer buf = new StringBuffer();
        if (!app.isConstructed()) {
            return indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "] (" + new String(Hex.encode(app.getContents())) + ")" + nl;
        }
        try {
            ASN1Sequence s = ASN1Sequence.getInstance(app.getObject(16));
            buf.append(indent + type + " ApplicationSpecific[" + app.getApplicationTag() + "]" + nl);
            Enumeration e = s.getObjects();
            while (e.hasMoreElements()) {
                _dumpAsString(indent + TAB, verbose, (DERObject) e.nextElement(), buf);
            }
        } catch (IOException e2) {
            buf.append(e2);
        }
        return buf.toString();
    }

    public static String dumpAsString(Object obj) {
        return dumpAsString(obj, false);
    }

    public static String dumpAsString(Object obj, boolean verbose) {
        StringBuffer buf = new StringBuffer();
        if (obj instanceof DERObject) {
            _dumpAsString("", verbose, (DERObject) obj, buf);
        } else if (!(obj instanceof DEREncodable)) {
            return "unknown object type " + obj.toString();
        } else {
            _dumpAsString("", verbose, ((DEREncodable) obj).getDERObject(), buf);
        }
        return buf.toString();
    }

    private static String dumpBinaryDataAsString(String indent, byte[] bytes) {
        String nl = System.getProperty("line.separator");
        StringBuffer buf = new StringBuffer();
        indent = indent + TAB;
        buf.append(nl);
        for (int i = 0; i < bytes.length; i += 32) {
            if (bytes.length - i > 32) {
                buf.append(indent);
                buf.append(new String(Hex.encode(bytes, i, 32)));
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, 32));
                buf.append(nl);
            } else {
                buf.append(indent);
                buf.append(new String(Hex.encode(bytes, i, bytes.length - i)));
                for (int j = bytes.length - i; j != 32; j++) {
                    buf.append("  ");
                }
                buf.append(TAB);
                buf.append(calculateAscString(bytes, i, bytes.length - i));
                buf.append(nl);
            }
        }
        return buf.toString();
    }

    private static String calculateAscString(byte[] bytes, int off, int len) {
        StringBuffer buf = new StringBuffer();
        int i = off;
        while (i != off + len) {
            if (bytes[i] >= (byte) 32 && bytes[i] <= (byte) 126) {
                buf.append((char) bytes[i]);
            }
            i++;
        }
        return buf.toString();
    }
}

package org.spongycastle.asn1.util;

import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;

public class DERDump extends ASN1Dump {
    public static String dumpAsString(DERObject obj) {
        StringBuffer buf = new StringBuffer();
        ASN1Dump._dumpAsString("", false, obj, buf);
        return buf.toString();
    }

    public static String dumpAsString(DEREncodable obj) {
        StringBuffer buf = new StringBuffer();
        ASN1Dump._dumpAsString("", false, obj.getDERObject(), buf);
        return buf.toString();
    }
}

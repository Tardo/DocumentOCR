package org.spongycastle.asn1.util;

import java.io.FileInputStream;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.DERObject;

public class Dump {
    public static void main(String[] args) throws Exception {
        ASN1InputStream bIn = new ASN1InputStream(new FileInputStream(args[0]));
        while (true) {
            DERObject obj = bIn.readObject();
            if (obj != null) {
                System.out.println(ASN1Dump.dumpAsString(obj));
            } else {
                return;
            }
        }
    }
}

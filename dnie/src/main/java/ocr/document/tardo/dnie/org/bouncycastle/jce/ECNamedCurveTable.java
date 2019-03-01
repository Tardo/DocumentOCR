package org.bouncycastle.jce;

import java.util.Enumeration;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

public class ECNamedCurveTable {
    private static void addEnumeration(Vector vector, Enumeration enumeration) {
        while (enumeration.hasMoreElements()) {
            vector.addElement(enumeration.nextElement());
        }
    }

    public static Enumeration getNames() {
        Vector vector = new Vector();
        addEnumeration(vector, X962NamedCurves.getNames());
        addEnumeration(vector, SECNamedCurves.getNames());
        addEnumeration(vector, NISTNamedCurves.getNames());
        addEnumeration(vector, TeleTrusTNamedCurves.getNames());
        return vector.elements();
    }

    public static ECNamedCurveParameterSpec getParameterSpec(String str) {
        X9ECParameters byName = X962NamedCurves.getByName(str);
        if (byName == null) {
            try {
                byName = X962NamedCurves.getByOID(new ASN1ObjectIdentifier(str));
            } catch (IllegalArgumentException e) {
            }
        }
        if (byName == null) {
            byName = SECNamedCurves.getByName(str);
            if (byName == null) {
                try {
                    byName = SECNamedCurves.getByOID(new ASN1ObjectIdentifier(str));
                } catch (IllegalArgumentException e2) {
                }
            }
        }
        if (byName == null) {
            byName = TeleTrusTNamedCurves.getByName(str);
            if (byName == null) {
                try {
                    byName = TeleTrusTNamedCurves.getByOID(new ASN1ObjectIdentifier(str));
                } catch (IllegalArgumentException e3) {
                }
            }
        }
        X9ECParameters byName2 = byName == null ? NISTNamedCurves.getByName(str) : byName;
        if (byName2 == null) {
            return null;
        }
        return new ECNamedCurveParameterSpec(str, byName2.getCurve(), byName2.getG(), byName2.getN(), byName2.getH(), byName2.getSeed());
    }
}

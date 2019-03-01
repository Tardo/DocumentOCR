package org.spongycastle.jce;

import java.util.Enumeration;
import java.util.Vector;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X962NamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;

public class ECNamedCurveTable {
    public static ECNamedCurveParameterSpec getParameterSpec(String name) {
        X9ECParameters ecP = X962NamedCurves.getByName(name);
        if (ecP == null) {
            try {
                ecP = X962NamedCurves.getByOID(new DERObjectIdentifier(name));
            } catch (IllegalArgumentException e) {
            }
        }
        if (ecP == null) {
            ecP = SECNamedCurves.getByName(name);
            if (ecP == null) {
                try {
                    ecP = SECNamedCurves.getByOID(new DERObjectIdentifier(name));
                } catch (IllegalArgumentException e2) {
                }
            }
        }
        if (ecP == null) {
            ecP = TeleTrusTNamedCurves.getByName(name);
            if (ecP == null) {
                try {
                    ecP = TeleTrusTNamedCurves.getByOID(new DERObjectIdentifier(name));
                } catch (IllegalArgumentException e3) {
                }
            }
        }
        if (ecP == null) {
            ecP = NISTNamedCurves.getByName(name);
        }
        if (ecP == null) {
            return null;
        }
        return new ECNamedCurveParameterSpec(name, ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }

    public static Enumeration getNames() {
        Vector v = new Vector();
        addEnumeration(v, X962NamedCurves.getNames());
        addEnumeration(v, SECNamedCurves.getNames());
        addEnumeration(v, NISTNamedCurves.getNames());
        addEnumeration(v, TeleTrusTNamedCurves.getNames());
        return v.elements();
    }

    private static void addEnumeration(Vector v, Enumeration e) {
        while (e.hasMoreElements()) {
            v.addElement(e.nextElement());
        }
    }
}

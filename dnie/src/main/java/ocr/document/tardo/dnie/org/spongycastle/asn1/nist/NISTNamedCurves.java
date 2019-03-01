package org.spongycastle.asn1.nist;

import java.util.Enumeration;
import java.util.Hashtable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.sec.SECObjectIdentifiers;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.util.Strings;

public class NISTNamedCurves {
    static final Hashtable names = new Hashtable();
    static final Hashtable objIds = new Hashtable();

    static {
        defineCurve("B-571", SECObjectIdentifiers.sect571r1);
        defineCurve("B-409", SECObjectIdentifiers.sect409r1);
        defineCurve("B-283", SECObjectIdentifiers.sect283r1);
        defineCurve("B-233", SECObjectIdentifiers.sect233r1);
        defineCurve("B-163", SECObjectIdentifiers.sect163r2);
        defineCurve("P-521", SECObjectIdentifiers.secp521r1);
        defineCurve("P-384", SECObjectIdentifiers.secp384r1);
        defineCurve("P-256", SECObjectIdentifiers.secp256r1);
        defineCurve("P-224", SECObjectIdentifiers.secp224r1);
        defineCurve("P-192", SECObjectIdentifiers.secp192r1);
    }

    static void defineCurve(String name, DERObjectIdentifier oid) {
        objIds.put(name, oid);
        names.put(oid, name);
    }

    public static X9ECParameters getByName(String name) {
        DERObjectIdentifier oid = (DERObjectIdentifier) objIds.get(Strings.toUpperCase(name));
        if (oid != null) {
            return getByOID(oid);
        }
        return null;
    }

    public static X9ECParameters getByOID(DERObjectIdentifier oid) {
        return SECNamedCurves.getByOID(oid);
    }

    public static DERObjectIdentifier getOID(String name) {
        return (DERObjectIdentifier) objIds.get(Strings.toUpperCase(name));
    }

    public static String getName(DERObjectIdentifier oid) {
        return (String) names.get(oid);
    }

    public static Enumeration getNames() {
        return objIds.keys();
    }
}

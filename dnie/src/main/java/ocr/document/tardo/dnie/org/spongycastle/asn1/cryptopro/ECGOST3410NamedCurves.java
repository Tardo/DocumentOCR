package org.spongycastle.asn1.cryptopro;

import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Hashtable;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;

public class ECGOST3410NamedCurves {
    static final Hashtable names = new Hashtable();
    static final Hashtable objIds = new Hashtable();
    static final Hashtable params = new Hashtable();

    static {
        BigInteger mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
        BigInteger mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");
        Fp curve = new Fp(mod_p, new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), new BigInteger("166"));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, new ECDomainParameters(curve, new ECPoint.Fp(curve, new ECFieldElement.Fp(curve.getQ(), new BigInteger("1")), new ECFieldElement.Fp(curve.getQ(), new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612"))), mod_q));
        mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319");
        mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");
        curve = new Fp(mod_p, new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), new BigInteger("166"));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, new ECDomainParameters(curve, new ECPoint.Fp(curve, new ECFieldElement.Fp(curve.getQ(), new BigInteger("1")), new ECFieldElement.Fp(curve.getQ(), new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612"))), mod_q));
        mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823193");
        mod_q = new BigInteger("57896044618658097711785492504343953927102133160255826820068844496087732066703");
        curve = new Fp(mod_p, new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823190"), new BigInteger("28091019353058090096996979000309560759124368558014865957655842872397301267595"));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, new ECDomainParameters(curve, new ECPoint.Fp(curve, new ECFieldElement.Fp(mod_p, new BigInteger("1")), new ECFieldElement.Fp(mod_p, new BigInteger("28792665814854611296992347458380284135028636778229113005756334730996303888124"))), mod_q));
        mod_p = new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502619");
        mod_q = new BigInteger("70390085352083305199547718019018437840920882647164081035322601458352298396601");
        curve = new Fp(mod_p, new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"), new BigInteger("32858"));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, new ECDomainParameters(curve, new ECPoint.Fp(curve, new ECFieldElement.Fp(mod_p, new BigInteger("0")), new ECFieldElement.Fp(mod_p, new BigInteger("29818893917731240733471273240314769927240550812383695689146495261604565990247"))), mod_q));
        mod_p = new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502619");
        mod_q = new BigInteger("70390085352083305199547718019018437840920882647164081035322601458352298396601");
        curve = new Fp(mod_p, new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"), new BigInteger("32858"));
        params.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, new ECDomainParameters(curve, new ECPoint.Fp(curve, new ECFieldElement.Fp(mod_p, new BigInteger("0")), new ECFieldElement.Fp(mod_p, new BigInteger("29818893917731240733471273240314769927240550812383695689146495261604565990247"))), mod_q));
        objIds.put("GostR3410-2001-CryptoPro-A", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        objIds.put("GostR3410-2001-CryptoPro-B", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        objIds.put("GostR3410-2001-CryptoPro-C", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        objIds.put("GostR3410-2001-CryptoPro-XchA", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        objIds.put("GostR3410-2001-CryptoPro-XchB", CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A, "GostR3410-2001-CryptoPro-A");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B, "GostR3410-2001-CryptoPro-B");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C, "GostR3410-2001-CryptoPro-C");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA, "GostR3410-2001-CryptoPro-XchA");
        names.put(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB, "GostR3410-2001-CryptoPro-XchB");
    }

    public static ECDomainParameters getByOID(DERObjectIdentifier oid) {
        return (ECDomainParameters) params.get(oid);
    }

    public static Enumeration getNames() {
        return objIds.keys();
    }

    public static ECDomainParameters getByName(String name) {
        DERObjectIdentifier oid = (DERObjectIdentifier) objIds.get(name);
        if (oid != null) {
            return (ECDomainParameters) params.get(oid);
        }
        return null;
    }

    public static String getName(DERObjectIdentifier oid) {
        return (String) names.get(oid);
    }

    public static DERObjectIdentifier getOID(String name) {
        return (DERObjectIdentifier) objIds.get(name);
    }
}

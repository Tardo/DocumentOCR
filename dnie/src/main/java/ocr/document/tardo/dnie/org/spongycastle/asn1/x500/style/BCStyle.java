package org.spongycastle.asn1.x500.style;

import java.io.IOException;
import java.util.Hashtable;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.DERGeneralizedTime;
import org.spongycastle.asn1.DERIA5String;
import org.spongycastle.asn1.DERPrintableString;
import org.spongycastle.asn1.DERUTF8String;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.AttributeTypeAndValue;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.X500NameStyle;
import org.spongycastle.asn1.x509.X509ObjectIdentifiers;

public class BCStyle implements X500NameStyle {
    public static final ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15");
    /* renamed from: C */
    public static final ASN1ObjectIdentifier f348C = new ASN1ObjectIdentifier("2.5.4.6");
    public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");
    public static final ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");
    public static final ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");
    public static final ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");
    public static final ASN1ObjectIdentifier DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");
    public static final ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");
    public static final ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46");
    private static final Hashtable DefaultLookUp = new Hashtable();
    private static final Hashtable DefaultSymbols = new Hashtable();
    /* renamed from: E */
    public static final ASN1ObjectIdentifier f349E = EmailAddress;
    public static final ASN1ObjectIdentifier EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    public static final ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");
    public static final ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
    public static final ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
    public static final ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
    public static final X500NameStyle INSTANCE = new BCStyle();
    /* renamed from: L */
    public static final ASN1ObjectIdentifier f350L = new ASN1ObjectIdentifier("2.5.4.7");
    public static final ASN1ObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;
    public static final ASN1ObjectIdentifier NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");
    /* renamed from: O */
    public static final ASN1ObjectIdentifier f351O = new ASN1ObjectIdentifier("2.5.4.10");
    public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");
    public static final ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");
    public static final ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");
    public static final ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17");
    public static final ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65");
    public static final ASN1ObjectIdentifier SERIALNUMBER = SN;
    public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");
    public static final ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");
    public static final ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");
    public static final ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
    /* renamed from: T */
    public static final ASN1ObjectIdentifier f352T = new ASN1ObjectIdentifier("2.5.4.12");
    public static final ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;
    public static final ASN1ObjectIdentifier UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");
    public static final ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");
    public static final ASN1ObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;
    public static final ASN1ObjectIdentifier UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;

    static {
        DefaultSymbols.put(f348C, "C");
        DefaultSymbols.put(f351O, "O");
        DefaultSymbols.put(f352T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(f350L, "L");
        DefaultSymbols.put(ST, "ST");
        DefaultSymbols.put(SN, "SERIALNUMBER");
        DefaultSymbols.put(EmailAddress, "E");
        DefaultSymbols.put(DC, "DC");
        DefaultSymbols.put(UID, "UID");
        DefaultSymbols.put(STREET, "STREET");
        DefaultSymbols.put(SURNAME, "SURNAME");
        DefaultSymbols.put(GIVENNAME, "GIVENNAME");
        DefaultSymbols.put(INITIALS, "INITIALS");
        DefaultSymbols.put(GENERATION, "GENERATION");
        DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
        DefaultSymbols.put(UnstructuredName, "unstructuredName");
        DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
        DefaultSymbols.put(DN_QUALIFIER, "DN");
        DefaultSymbols.put(PSEUDONYM, "Pseudonym");
        DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
        DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
        DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
        DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
        DefaultSymbols.put(GENDER, "Gender");
        DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
        DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
        DefaultSymbols.put(POSTAL_CODE, "PostalCode");
        DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
        DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
        DefaultSymbols.put(NAME, "Name");
        DefaultLookUp.put("c", f348C);
        DefaultLookUp.put("o", f351O);
        DefaultLookUp.put("t", f352T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", f350L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", f349E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", f349E);
        DefaultLookUp.put("uid", UID);
        DefaultLookUp.put("surname", SURNAME);
        DefaultLookUp.put("givenname", GIVENNAME);
        DefaultLookUp.put("initials", INITIALS);
        DefaultLookUp.put("generation", GENERATION);
        DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
        DefaultLookUp.put("unstructuredname", UnstructuredName);
        DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
        DefaultLookUp.put("dn", DN_QUALIFIER);
        DefaultLookUp.put("pseudonym", PSEUDONYM);
        DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
        DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
        DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
        DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
        DefaultLookUp.put("gender", GENDER);
        DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
        DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
        DefaultLookUp.put("postalcode", POSTAL_CODE);
        DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
        DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
        DefaultLookUp.put("name", NAME);
    }

    protected BCStyle() {
    }

    public ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, String value) {
        if (value.length() == 0 || value.charAt(0) != '#') {
            if (value.length() != 0 && value.charAt(0) == '\\') {
                value = value.substring(1);
            }
            if (oid.equals(EmailAddress) || oid.equals(DC)) {
                return new DERIA5String(value);
            }
            if (oid.equals(DATE_OF_BIRTH)) {
                return new DERGeneralizedTime(value);
            }
            if (oid.equals(f348C) || oid.equals(SN) || oid.equals(DN_QUALIFIER) || oid.equals(TELEPHONE_NUMBER)) {
                return new DERPrintableString(value);
            }
            return new DERUTF8String(value);
        }
        try {
            return IETFUtils.valueFromHexString(value, 1);
        } catch (IOException e) {
            throw new RuntimeException("can't recode value for oid " + oid.getId());
        }
    }

    public ASN1ObjectIdentifier attrNameToOID(String attrName) {
        return IETFUtils.decodeAttrName(attrName, DefaultLookUp);
    }

    public boolean areEqual(X500Name name1, X500Name name2) {
        RDN[] rdns1 = name1.getRDNs();
        RDN[] rdns2 = name2.getRDNs();
        if (rdns1.length != rdns2.length) {
            return false;
        }
        boolean reverse = false;
        if (!(rdns1[0].getFirst() == null || rdns2[0].getFirst() == null)) {
            reverse = !rdns1[0].getFirst().getType().equals(rdns2[0].getFirst().getType());
        }
        for (int i = 0; i != rdns1.length; i++) {
            if (!foundMatch(reverse, rdns1[i], rdns2)) {
                return false;
            }
        }
        return true;
    }

    private boolean foundMatch(boolean reverse, RDN rdn, RDN[] possRDNs) {
        int i;
        if (reverse) {
            i = possRDNs.length - 1;
            while (i >= 0) {
                if (possRDNs[i] == null || !rdnAreEqual(rdn, possRDNs[i])) {
                    i--;
                } else {
                    possRDNs[i] = null;
                    return true;
                }
            }
        }
        i = 0;
        while (i != possRDNs.length) {
            if (possRDNs[i] == null || !rdnAreEqual(rdn, possRDNs[i])) {
                i++;
            } else {
                possRDNs[i] = null;
                return true;
            }
        }
        return false;
    }

    protected boolean rdnAreEqual(RDN rdn1, RDN rdn2) {
        if (rdn1.isMultiValued()) {
            if (!rdn2.isMultiValued()) {
                return false;
            }
            AttributeTypeAndValue[] atvs1 = rdn1.getTypesAndValues();
            AttributeTypeAndValue[] atvs2 = rdn2.getTypesAndValues();
            if (atvs1.length != atvs2.length) {
                return false;
            }
            for (int i = 0; i != atvs1.length; i++) {
                if (!atvAreEqual(atvs1[i], atvs2[i])) {
                    return false;
                }
            }
            return true;
        } else if (rdn2.isMultiValued()) {
            return false;
        } else {
            return atvAreEqual(rdn1.getFirst(), rdn2.getFirst());
        }
    }

    private boolean atvAreEqual(AttributeTypeAndValue atv1, AttributeTypeAndValue atv2) {
        if (atv1 == atv2) {
            return true;
        }
        if (atv1 == null) {
            return false;
        }
        if (atv2 == null) {
            return false;
        }
        if (!atv1.getType().equals(atv2.getType())) {
            return false;
        }
        if (IETFUtils.canonicalize(IETFUtils.valueToString(atv1.getValue())).equals(IETFUtils.canonicalize(IETFUtils.valueToString(atv2.getValue())))) {
            return true;
        }
        return false;
    }

    public RDN[] fromString(String dirName) {
        return IETFUtils.rDNsFromString(dirName, this);
    }

    public int calculateHashCode(X500Name name) {
        int hashCodeValue = 0;
        RDN[] rdns = name.getRDNs();
        for (int i = 0; i != rdns.length; i++) {
            if (rdns[i].isMultiValued()) {
                AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
                for (int j = 0; j != atv.length; j++) {
                    hashCodeValue = (hashCodeValue ^ atv[j].getType().hashCode()) ^ calcHashCode(atv[j].getValue());
                }
            } else {
                hashCodeValue = (hashCodeValue ^ rdns[i].getFirst().getType().hashCode()) ^ calcHashCode(rdns[i].getFirst().getValue());
            }
        }
        return hashCodeValue;
    }

    private int calcHashCode(ASN1Encodable enc) {
        return IETFUtils.canonicalize(IETFUtils.valueToString(enc)).hashCode();
    }

    public String toString(X500Name name) {
        StringBuffer buf = new StringBuffer();
        boolean first = true;
        RDN[] rdns = name.getRDNs();
        for (int i = 0; i < rdns.length; i++) {
            if (first) {
                first = false;
            } else {
                buf.append(',');
            }
            if (rdns[i].isMultiValued()) {
                AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();
                boolean firstAtv = true;
                for (int j = 0; j != atv.length; j++) {
                    if (firstAtv) {
                        firstAtv = false;
                    } else {
                        buf.append('+');
                    }
                    IETFUtils.appendTypeAndValue(buf, atv[j], DefaultSymbols);
                }
            } else {
                IETFUtils.appendTypeAndValue(buf, rdns[i].getFirst(), DefaultSymbols);
            }
        }
        return buf.toString();
    }
}

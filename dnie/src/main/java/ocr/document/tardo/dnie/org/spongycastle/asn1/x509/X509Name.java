package org.spongycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Object;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Set;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEREncodable;
import org.spongycastle.asn1.DERObject;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERSet;
import org.spongycastle.asn1.DERString;
import org.spongycastle.asn1.DERUniversalString;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.util.Strings;
import org.spongycastle.util.encoders.Hex;

public class X509Name extends ASN1Encodable {
    public static final DERObjectIdentifier BUSINESS_CATEGORY = new DERObjectIdentifier("2.5.4.15");
    /* renamed from: C */
    public static final DERObjectIdentifier f551C = new DERObjectIdentifier("2.5.4.6");
    public static final DERObjectIdentifier CN = new DERObjectIdentifier("2.5.4.3");
    public static final DERObjectIdentifier COUNTRY_OF_CITIZENSHIP = new DERObjectIdentifier("1.3.6.1.5.5.7.9.4");
    public static final DERObjectIdentifier COUNTRY_OF_RESIDENCE = new DERObjectIdentifier("1.3.6.1.5.5.7.9.5");
    public static final DERObjectIdentifier DATE_OF_BIRTH = new DERObjectIdentifier("1.3.6.1.5.5.7.9.1");
    public static final DERObjectIdentifier DC = new DERObjectIdentifier("0.9.2342.19200300.100.1.25");
    public static final DERObjectIdentifier DMD_NAME = new DERObjectIdentifier("2.5.4.54");
    public static final DERObjectIdentifier DN_QUALIFIER = new DERObjectIdentifier("2.5.4.46");
    public static final Hashtable DefaultLookUp = new Hashtable();
    public static boolean DefaultReverse = false;
    public static final Hashtable DefaultSymbols = new Hashtable();
    /* renamed from: E */
    public static final DERObjectIdentifier f552E = EmailAddress;
    public static final DERObjectIdentifier EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    private static final Boolean FALSE = new Boolean(false);
    public static final DERObjectIdentifier GENDER = new DERObjectIdentifier("1.3.6.1.5.5.7.9.3");
    public static final DERObjectIdentifier GENERATION = new DERObjectIdentifier("2.5.4.44");
    public static final DERObjectIdentifier GIVENNAME = new DERObjectIdentifier("2.5.4.42");
    public static final DERObjectIdentifier INITIALS = new DERObjectIdentifier("2.5.4.43");
    /* renamed from: L */
    public static final DERObjectIdentifier f553L = new DERObjectIdentifier("2.5.4.7");
    public static final DERObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;
    public static final DERObjectIdentifier NAME_AT_BIRTH = new DERObjectIdentifier("1.3.36.8.3.14");
    /* renamed from: O */
    public static final DERObjectIdentifier f554O = new DERObjectIdentifier("2.5.4.10");
    public static final Hashtable OIDLookUp = DefaultSymbols;
    public static final DERObjectIdentifier OU = new DERObjectIdentifier("2.5.4.11");
    public static final DERObjectIdentifier PLACE_OF_BIRTH = new DERObjectIdentifier("1.3.6.1.5.5.7.9.2");
    public static final DERObjectIdentifier POSTAL_ADDRESS = new DERObjectIdentifier("2.5.4.16");
    public static final DERObjectIdentifier POSTAL_CODE = new DERObjectIdentifier("2.5.4.17");
    public static final DERObjectIdentifier PSEUDONYM = new DERObjectIdentifier("2.5.4.65");
    public static final Hashtable RFC1779Symbols = new Hashtable();
    public static final Hashtable RFC2253Symbols = new Hashtable();
    public static final DERObjectIdentifier SERIALNUMBER = SN;
    public static final DERObjectIdentifier SN = new DERObjectIdentifier("2.5.4.5");
    public static final DERObjectIdentifier ST = new DERObjectIdentifier("2.5.4.8");
    public static final DERObjectIdentifier STREET = new DERObjectIdentifier("2.5.4.9");
    public static final DERObjectIdentifier SURNAME = new DERObjectIdentifier("2.5.4.4");
    public static final Hashtable SymbolLookUp = DefaultLookUp;
    /* renamed from: T */
    public static final DERObjectIdentifier f555T = new DERObjectIdentifier("2.5.4.12");
    public static final DERObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;
    private static final Boolean TRUE = new Boolean(true);
    public static final DERObjectIdentifier UID = new DERObjectIdentifier("0.9.2342.19200300.100.1.1");
    public static final DERObjectIdentifier UNIQUE_IDENTIFIER = new DERObjectIdentifier("2.5.4.45");
    public static final DERObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;
    public static final DERObjectIdentifier UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    private Vector added;
    private X509NameEntryConverter converter;
    private int hashCodeValue;
    private boolean isHashCodeCalculated;
    private Vector ordering;
    private ASN1Sequence seq;
    private Vector values;

    static {
        DefaultSymbols.put(f551C, "C");
        DefaultSymbols.put(f554O, "O");
        DefaultSymbols.put(f555T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(f553L, "L");
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
        RFC2253Symbols.put(f551C, "C");
        RFC2253Symbols.put(f554O, "O");
        RFC2253Symbols.put(OU, "OU");
        RFC2253Symbols.put(CN, "CN");
        RFC2253Symbols.put(f553L, "L");
        RFC2253Symbols.put(ST, "ST");
        RFC2253Symbols.put(STREET, "STREET");
        RFC2253Symbols.put(DC, "DC");
        RFC2253Symbols.put(UID, "UID");
        RFC1779Symbols.put(f551C, "C");
        RFC1779Symbols.put(f554O, "O");
        RFC1779Symbols.put(OU, "OU");
        RFC1779Symbols.put(CN, "CN");
        RFC1779Symbols.put(f553L, "L");
        RFC1779Symbols.put(ST, "ST");
        RFC1779Symbols.put(STREET, "STREET");
        DefaultLookUp.put("c", f551C);
        DefaultLookUp.put("o", f554O);
        DefaultLookUp.put("t", f555T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", f553L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", f552E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", f552E);
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

    public static X509Name getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static X509Name getInstance(Object obj) {
        if (obj == null || (obj instanceof X509Name)) {
            return (X509Name) obj;
        }
        if (obj instanceof X500Name) {
            return new X509Name(ASN1Sequence.getInstance(((X500Name) obj).getDERObject()));
        }
        if (obj != null) {
            return new X509Name(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    protected X509Name() {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
    }

    public X509Name(ASN1Sequence seq) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.seq = seq;
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1Set set = ASN1Set.getInstance(((DEREncodable) e.nextElement()).getDERObject());
            for (int i = 0; i < set.size(); i++) {
                ASN1Sequence s = ASN1Sequence.getInstance(set.getObjectAt(i));
                if (s.size() != 2) {
                    throw new IllegalArgumentException("badly sized pair");
                }
                Object obj;
                this.ordering.addElement(DERObjectIdentifier.getInstance(s.getObjectAt(0)));
                DEREncodable value = s.getObjectAt(1);
                if (!(value instanceof DERString) || (value instanceof DERUniversalString)) {
                    this.values.addElement("#" + bytesToString(Hex.encode(value.getDERObject().getDEREncoded())));
                } else {
                    String v = ((DERString) value).getString();
                    if (v.length() <= 0 || v.charAt(0) != '#') {
                        this.values.addElement(v);
                    } else {
                        this.values.addElement("\\" + v);
                    }
                }
                Vector vector = this.added;
                if (i != 0) {
                    obj = TRUE;
                } else {
                    obj = FALSE;
                }
                vector.addElement(obj);
            }
        }
    }

    public X509Name(Hashtable attributes) {
        this(null, attributes);
    }

    public X509Name(Vector ordering, Hashtable attributes) {
        this(ordering, attributes, new X509DefaultEntryConverter());
    }

    public X509Name(Vector ordering, Hashtable attributes, X509NameEntryConverter converter) {
        int i;
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = converter;
        if (ordering != null) {
            for (i = 0; i != ordering.size(); i++) {
                this.ordering.addElement(ordering.elementAt(i));
                this.added.addElement(FALSE);
            }
        } else {
            Enumeration e = attributes.keys();
            while (e.hasMoreElements()) {
                this.ordering.addElement(e.nextElement());
                this.added.addElement(FALSE);
            }
        }
        for (i = 0; i != this.ordering.size(); i++) {
            DERObjectIdentifier oid = (DERObjectIdentifier) this.ordering.elementAt(i);
            if (attributes.get(oid) == null) {
                throw new IllegalArgumentException("No attribute for object id - " + oid.getId() + " - passed to distinguished name");
            }
            this.values.addElement(attributes.get(oid));
        }
    }

    public X509Name(Vector oids, Vector values) {
        this(oids, values, new X509DefaultEntryConverter());
    }

    public X509Name(Vector oids, Vector values, X509NameEntryConverter converter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = converter;
        if (oids.size() != values.size()) {
            throw new IllegalArgumentException("oids vector must be same length as values.");
        }
        for (int i = 0; i < oids.size(); i++) {
            this.ordering.addElement(oids.elementAt(i));
            this.values.addElement(values.elementAt(i));
            this.added.addElement(FALSE);
        }
    }

    public X509Name(String dirName) {
        this(DefaultReverse, DefaultLookUp, dirName);
    }

    public X509Name(String dirName, X509NameEntryConverter converter) {
        this(DefaultReverse, DefaultLookUp, dirName, converter);
    }

    public X509Name(boolean reverse, String dirName) {
        this(reverse, DefaultLookUp, dirName);
    }

    public X509Name(boolean reverse, String dirName, X509NameEntryConverter converter) {
        this(reverse, DefaultLookUp, dirName, converter);
    }

    public X509Name(boolean reverse, Hashtable lookUp, String dirName) {
        this(reverse, lookUp, dirName, new X509DefaultEntryConverter());
    }

    private DERObjectIdentifier decodeOID(String name, Hashtable lookUp) {
        if (Strings.toUpperCase(name).startsWith("OID.")) {
            return new DERObjectIdentifier(name.substring(4));
        }
        if (name.charAt(0) >= '0' && name.charAt(0) <= '9') {
            return new DERObjectIdentifier(name);
        }
        DERObjectIdentifier oid = (DERObjectIdentifier) lookUp.get(Strings.toLowerCase(name));
        if (oid != null) {
            return oid;
        }
        throw new IllegalArgumentException("Unknown object id - " + name + " - passed to distinguished name");
    }

    public X509Name(boolean reverse, Hashtable lookUp, String dirName, X509NameEntryConverter converter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = converter;
        X509NameTokenizer nTok = new X509NameTokenizer(dirName);
        while (nTok.hasMoreTokens()) {
            String token = nTok.nextToken();
            int index = token.indexOf(61);
            if (index == -1) {
                throw new IllegalArgumentException("badly formated directory string");
            }
            String name = token.substring(0, index);
            String value = token.substring(index + 1);
            DERObjectIdentifier oid = decodeOID(name, lookUp);
            if (value.indexOf(43) > 0) {
                X509NameTokenizer vTok = new X509NameTokenizer(value, '+');
                String v = vTok.nextToken();
                this.ordering.addElement(oid);
                this.values.addElement(v);
                this.added.addElement(FALSE);
                while (vTok.hasMoreTokens()) {
                    String sv = vTok.nextToken();
                    int ndx = sv.indexOf(61);
                    String nm = sv.substring(0, ndx);
                    String vl = sv.substring(ndx + 1);
                    this.ordering.addElement(decodeOID(nm, lookUp));
                    this.values.addElement(vl);
                    this.added.addElement(TRUE);
                }
            } else {
                this.ordering.addElement(oid);
                this.values.addElement(value);
                this.added.addElement(FALSE);
            }
        }
        if (reverse) {
            Vector o = new Vector();
            Vector v2 = new Vector();
            Vector a = new Vector();
            int count = 1;
            for (int i = 0; i < this.ordering.size(); i++) {
                if (((Boolean) this.added.elementAt(i)).booleanValue()) {
                    o.insertElementAt(this.ordering.elementAt(i), count);
                    v2.insertElementAt(this.values.elementAt(i), count);
                    a.insertElementAt(this.added.elementAt(i), count);
                    count++;
                } else {
                    o.insertElementAt(this.ordering.elementAt(i), 0);
                    v2.insertElementAt(this.values.elementAt(i), 0);
                    a.insertElementAt(this.added.elementAt(i), 0);
                    count = 1;
                }
            }
            this.ordering = o;
            this.values = v2;
            this.added = a;
        }
    }

    public Vector getOIDs() {
        Vector v = new Vector();
        for (int i = 0; i != this.ordering.size(); i++) {
            v.addElement(this.ordering.elementAt(i));
        }
        return v;
    }

    public Vector getValues() {
        Vector v = new Vector();
        for (int i = 0; i != this.values.size(); i++) {
            v.addElement(this.values.elementAt(i));
        }
        return v;
    }

    public Vector getValues(DERObjectIdentifier oid) {
        Vector v = new Vector();
        for (int i = 0; i != this.values.size(); i++) {
            if (this.ordering.elementAt(i).equals(oid)) {
                String val = (String) this.values.elementAt(i);
                if (val.length() > 2 && val.charAt(0) == '\\' && val.charAt(1) == '#') {
                    v.addElement(val.substring(1));
                } else {
                    v.addElement(val);
                }
            }
        }
        return v;
    }

    public DERObject toASN1Object() {
        if (this.seq == null) {
            ASN1EncodableVector vec = new ASN1EncodableVector();
            ASN1EncodableVector sVec = new ASN1EncodableVector();
            DERObjectIdentifier lstOid = null;
            int i = 0;
            while (i != this.ordering.size()) {
                ASN1EncodableVector v = new ASN1EncodableVector();
                DERObjectIdentifier oid = (DERObjectIdentifier) this.ordering.elementAt(i);
                v.add(oid);
                v.add(this.converter.getConvertedValue(oid, (String) this.values.elementAt(i)));
                if (lstOid == null || ((Boolean) this.added.elementAt(i)).booleanValue()) {
                    sVec.add(new DERSequence(v));
                } else {
                    vec.add(new DERSet(sVec));
                    sVec = new ASN1EncodableVector();
                    sVec.add(new DERSequence(v));
                }
                lstOid = oid;
                i++;
            }
            vec.add(new DERSet(sVec));
            this.seq = new DERSequence(vec);
        }
        return this.seq;
    }

    public boolean equals(Object obj, boolean inOrder) {
        if (!inOrder) {
            return equals(obj);
        }
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof X509Name) && !(obj instanceof ASN1Sequence)) {
            return false;
        }
        if (getDERObject().equals(((DEREncodable) obj).getDERObject())) {
            return true;
        }
        try {
            X509Name other = getInstance(obj);
            int orderingSize = this.ordering.size();
            if (orderingSize != other.ordering.size()) {
                return false;
            }
            for (int i = 0; i < orderingSize; i++) {
                if (!((DERObjectIdentifier) this.ordering.elementAt(i)).equals((DERObjectIdentifier) other.ordering.elementAt(i))) {
                    return false;
                }
                if (!equivalentStrings((String) this.values.elementAt(i), (String) other.values.elementAt(i))) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public int hashCode() {
        if (this.isHashCodeCalculated) {
            return this.hashCodeValue;
        }
        this.isHashCodeCalculated = true;
        for (int i = 0; i != this.ordering.size(); i++) {
            String value = stripInternalSpaces(canonicalize((String) this.values.elementAt(i)));
            this.hashCodeValue ^= this.ordering.elementAt(i).hashCode();
            this.hashCodeValue ^= value.hashCode();
        }
        return this.hashCodeValue;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof X509Name) && !(obj instanceof ASN1Sequence)) {
            return false;
        }
        if (getDERObject().equals(((DEREncodable) obj).getDERObject())) {
            return true;
        }
        try {
            X509Name other = getInstance(obj);
            int orderingSize = this.ordering.size();
            if (orderingSize != other.ordering.size()) {
                return false;
            }
            int start;
            int end;
            int delta;
            boolean[] indexes = new boolean[orderingSize];
            if (this.ordering.elementAt(0).equals(other.ordering.elementAt(0))) {
                start = 0;
                end = orderingSize;
                delta = 1;
            } else {
                start = orderingSize - 1;
                end = -1;
                delta = -1;
            }
            for (int i = start; i != end; i += delta) {
                boolean found = false;
                DERObjectIdentifier oid = (DERObjectIdentifier) this.ordering.elementAt(i);
                String value = (String) this.values.elementAt(i);
                int j = 0;
                while (j < orderingSize) {
                    if (!indexes[j] && oid.equals((DERObjectIdentifier) other.ordering.elementAt(j))) {
                        if (equivalentStrings(value, (String) other.values.elementAt(j))) {
                            indexes[j] = true;
                            found = true;
                            break;
                        }
                    }
                    j++;
                }
                if (!found) {
                    return false;
                }
            }
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean equivalentStrings(String s1, String s2) {
        String value = canonicalize(s1);
        String oValue = canonicalize(s2);
        if (value.equals(oValue) || stripInternalSpaces(value).equals(stripInternalSpaces(oValue))) {
            return true;
        }
        return false;
    }

    private String canonicalize(String s) {
        String value = Strings.toLowerCase(s.trim());
        if (value.length() <= 0 || value.charAt(0) != '#') {
            return value;
        }
        DERObject obj = decodeObject(value);
        if (obj instanceof DERString) {
            return Strings.toLowerCase(((DERString) obj).getString().trim());
        }
        return value;
    }

    private ASN1Object decodeObject(String oValue) {
        try {
            return ASN1Object.fromByteArray(Hex.decode(oValue.substring(1)));
        } catch (IOException e) {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    private String stripInternalSpaces(String str) {
        StringBuffer res = new StringBuffer();
        if (str.length() != 0) {
            char c1 = str.charAt(0);
            res.append(c1);
            for (int k = 1; k < str.length(); k++) {
                char c2 = str.charAt(k);
                if (c1 != ' ' || c2 != ' ') {
                    res.append(c2);
                }
                c1 = c2;
            }
        }
        return res.toString();
    }

    private void appendValue(StringBuffer buf, Hashtable oidSymbols, DERObjectIdentifier oid, String value) {
        String sym = (String) oidSymbols.get(oid);
        if (sym != null) {
            buf.append(sym);
        } else {
            buf.append(oid.getId());
        }
        buf.append('=');
        int index = buf.length();
        buf.append(value);
        int end = buf.length();
        if (value.length() >= 2 && value.charAt(0) == '\\' && value.charAt(1) == '#') {
            index += 2;
        }
        while (index != end) {
            if (buf.charAt(index) == ',' || buf.charAt(index) == '\"' || buf.charAt(index) == '\\' || buf.charAt(index) == '+' || buf.charAt(index) == '=' || buf.charAt(index) == '<' || buf.charAt(index) == '>' || buf.charAt(index) == ';') {
                buf.insert(index, "\\");
                index++;
                end++;
            }
            index++;
        }
    }

    public String toString(boolean reverse, Hashtable oidSymbols) {
        int i;
        StringBuffer buf = new StringBuffer();
        Vector components = new Vector();
        boolean first = true;
        StringBuffer ava = null;
        for (i = 0; i < this.ordering.size(); i++) {
            if (((Boolean) this.added.elementAt(i)).booleanValue()) {
                ava.append('+');
                appendValue(ava, oidSymbols, (DERObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
            } else {
                ava = new StringBuffer();
                appendValue(ava, oidSymbols, (DERObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
                components.addElement(ava);
            }
        }
        if (reverse) {
            for (i = components.size() - 1; i >= 0; i--) {
                if (first) {
                    first = false;
                } else {
                    buf.append(',');
                }
                buf.append(components.elementAt(i).toString());
            }
        } else {
            for (i = 0; i < components.size(); i++) {
                if (first) {
                    first = false;
                } else {
                    buf.append(',');
                }
                buf.append(components.elementAt(i).toString());
            }
        }
        return buf.toString();
    }

    private String bytesToString(byte[] data) {
        char[] cs = new char[data.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char) (data[i] & 255);
        }
        return new String(cs);
    }

    public String toString() {
        return toString(DefaultReverse, DefaultSymbols);
    }
}

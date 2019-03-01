package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class X509Name extends ASN1Object {
    public static final ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15");
    /* renamed from: C */
    public static final ASN1ObjectIdentifier f463C = new ASN1ObjectIdentifier("2.5.4.6");
    public static final ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");
    public static final ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");
    public static final ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");
    public static final ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");
    public static final ASN1ObjectIdentifier DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");
    public static final ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");
    public static final ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46");
    public static final Hashtable DefaultLookUp = new Hashtable();
    public static boolean DefaultReverse = false;
    public static final Hashtable DefaultSymbols = new Hashtable();
    /* renamed from: E */
    public static final ASN1ObjectIdentifier f464E = EmailAddress;
    public static final ASN1ObjectIdentifier EmailAddress = PKCSObjectIdentifiers.pkcs_9_at_emailAddress;
    private static final Boolean FALSE = new Boolean(false);
    public static final ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");
    public static final ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
    public static final ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
    public static final ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
    /* renamed from: L */
    public static final ASN1ObjectIdentifier f465L = new ASN1ObjectIdentifier("2.5.4.7");
    public static final ASN1ObjectIdentifier NAME = X509ObjectIdentifiers.id_at_name;
    public static final ASN1ObjectIdentifier NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");
    /* renamed from: O */
    public static final ASN1ObjectIdentifier f466O = new ASN1ObjectIdentifier("2.5.4.10");
    public static final Hashtable OIDLookUp = DefaultSymbols;
    public static final ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");
    public static final ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");
    public static final ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");
    public static final ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17");
    public static final ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65");
    public static final Hashtable RFC1779Symbols = new Hashtable();
    public static final Hashtable RFC2253Symbols = new Hashtable();
    public static final ASN1ObjectIdentifier SERIALNUMBER = SN;
    public static final ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");
    public static final ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");
    public static final ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");
    public static final ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
    public static final Hashtable SymbolLookUp = DefaultLookUp;
    /* renamed from: T */
    public static final ASN1ObjectIdentifier f467T = new ASN1ObjectIdentifier("2.5.4.12");
    public static final ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers.id_at_telephoneNumber;
    private static final Boolean TRUE = new Boolean(true);
    public static final ASN1ObjectIdentifier UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");
    public static final ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");
    public static final ASN1ObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers.pkcs_9_at_unstructuredAddress;
    public static final ASN1ObjectIdentifier UnstructuredName = PKCSObjectIdentifiers.pkcs_9_at_unstructuredName;
    private Vector added;
    private X509NameEntryConverter converter;
    private int hashCodeValue;
    private boolean isHashCodeCalculated;
    private Vector ordering;
    private ASN1Sequence seq;
    private Vector values;

    static {
        DefaultSymbols.put(f463C, "C");
        DefaultSymbols.put(f466O, "O");
        DefaultSymbols.put(f467T, "T");
        DefaultSymbols.put(OU, "OU");
        DefaultSymbols.put(CN, "CN");
        DefaultSymbols.put(f465L, "L");
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
        RFC2253Symbols.put(f463C, "C");
        RFC2253Symbols.put(f466O, "O");
        RFC2253Symbols.put(OU, "OU");
        RFC2253Symbols.put(CN, "CN");
        RFC2253Symbols.put(f465L, "L");
        RFC2253Symbols.put(ST, "ST");
        RFC2253Symbols.put(STREET, "STREET");
        RFC2253Symbols.put(DC, "DC");
        RFC2253Symbols.put(UID, "UID");
        RFC1779Symbols.put(f463C, "C");
        RFC1779Symbols.put(f466O, "O");
        RFC1779Symbols.put(OU, "OU");
        RFC1779Symbols.put(CN, "CN");
        RFC1779Symbols.put(f465L, "L");
        RFC1779Symbols.put(ST, "ST");
        RFC1779Symbols.put(STREET, "STREET");
        DefaultLookUp.put("c", f463C);
        DefaultLookUp.put("o", f466O);
        DefaultLookUp.put("t", f467T);
        DefaultLookUp.put("ou", OU);
        DefaultLookUp.put("cn", CN);
        DefaultLookUp.put("l", f465L);
        DefaultLookUp.put("st", ST);
        DefaultLookUp.put("sn", SN);
        DefaultLookUp.put("serialnumber", SN);
        DefaultLookUp.put("street", STREET);
        DefaultLookUp.put("emailaddress", f464E);
        DefaultLookUp.put("dc", DC);
        DefaultLookUp.put("e", f464E);
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

    protected X509Name() {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
    }

    public X509Name(String str) {
        this(DefaultReverse, DefaultLookUp, str);
    }

    public X509Name(String str, X509NameEntryConverter x509NameEntryConverter) {
        this(DefaultReverse, DefaultLookUp, str, x509NameEntryConverter);
    }

    public X509Name(Hashtable hashtable) {
        this(null, hashtable);
    }

    public X509Name(Vector vector, Hashtable hashtable) {
        this(vector, hashtable, new X509DefaultEntryConverter());
    }

    public X509Name(Vector vector, Hashtable hashtable, X509NameEntryConverter x509NameEntryConverter) {
        int i = 0;
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = x509NameEntryConverter;
        if (vector != null) {
            for (int i2 = 0; i2 != vector.size(); i2++) {
                this.ordering.addElement(vector.elementAt(i2));
                this.added.addElement(FALSE);
            }
        } else {
            Enumeration keys = hashtable.keys();
            while (keys.hasMoreElements()) {
                this.ordering.addElement(keys.nextElement());
                this.added.addElement(FALSE);
            }
        }
        while (i != this.ordering.size()) {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) this.ordering.elementAt(i);
            if (hashtable.get(aSN1ObjectIdentifier) == null) {
                throw new IllegalArgumentException("No attribute for object id - " + aSN1ObjectIdentifier.getId() + " - passed to distinguished name");
            }
            this.values.addElement(hashtable.get(aSN1ObjectIdentifier));
            i++;
        }
    }

    public X509Name(Vector vector, Vector vector2) {
        this(vector, vector2, new X509DefaultEntryConverter());
    }

    public X509Name(Vector vector, Vector vector2, X509NameEntryConverter x509NameEntryConverter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = x509NameEntryConverter;
        if (vector.size() != vector2.size()) {
            throw new IllegalArgumentException("oids vector must be same length as values.");
        }
        for (int i = 0; i < vector.size(); i++) {
            this.ordering.addElement(vector.elementAt(i));
            this.values.addElement(vector2.elementAt(i));
            this.added.addElement(FALSE);
        }
    }

    public X509Name(ASN1Sequence aSN1Sequence) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.seq = aSN1Sequence;
        Enumeration objects = aSN1Sequence.getObjects();
        while (objects.hasMoreElements()) {
            ASN1Set instance = ASN1Set.getInstance(((ASN1Encodable) objects.nextElement()).toASN1Primitive());
            int i = 0;
            while (i < instance.size()) {
                ASN1Sequence instance2 = ASN1Sequence.getInstance(instance.getObjectAt(i).toASN1Primitive());
                if (instance2.size() != 2) {
                    throw new IllegalArgumentException("badly sized pair");
                }
                this.ordering.addElement(DERObjectIdentifier.getInstance(instance2.getObjectAt(0)));
                ASN1Encodable objectAt = instance2.getObjectAt(1);
                if (!(objectAt instanceof ASN1String) || (objectAt instanceof DERUniversalString)) {
                    try {
                        this.values.addElement("#" + bytesToString(Hex.encode(objectAt.toASN1Primitive().getEncoded("DER"))));
                    } catch (IOException e) {
                        throw new IllegalArgumentException("cannot encode value");
                    }
                }
                String string = ((ASN1String) objectAt).getString();
                if (string.length() <= 0 || string.charAt(0) != '#') {
                    this.values.addElement(string);
                } else {
                    this.values.addElement("\\" + string);
                }
                this.added.addElement(i != 0 ? TRUE : FALSE);
                i++;
            }
        }
    }

    public X509Name(boolean z, String str) {
        this(z, DefaultLookUp, str);
    }

    public X509Name(boolean z, String str, X509NameEntryConverter x509NameEntryConverter) {
        this(z, DefaultLookUp, str, x509NameEntryConverter);
    }

    public X509Name(boolean z, Hashtable hashtable, String str) {
        this(z, hashtable, str, new X509DefaultEntryConverter());
    }

    public X509Name(boolean z, Hashtable hashtable, String str, X509NameEntryConverter x509NameEntryConverter) {
        this.converter = null;
        this.ordering = new Vector();
        this.values = new Vector();
        this.added = new Vector();
        this.converter = x509NameEntryConverter;
        X509NameTokenizer x509NameTokenizer = new X509NameTokenizer(str);
        while (x509NameTokenizer.hasMoreTokens()) {
            String nextToken = x509NameTokenizer.nextToken();
            if (nextToken.indexOf(43) > 0) {
                X509NameTokenizer x509NameTokenizer2 = new X509NameTokenizer(nextToken, '+');
                addEntry(hashtable, x509NameTokenizer2.nextToken(), FALSE);
                while (x509NameTokenizer2.hasMoreTokens()) {
                    addEntry(hashtable, x509NameTokenizer2.nextToken(), TRUE);
                }
            } else {
                addEntry(hashtable, nextToken, FALSE);
            }
        }
        if (z) {
            Vector vector = new Vector();
            Vector vector2 = new Vector();
            Vector vector3 = new Vector();
            int i = 1;
            for (int i2 = 0; i2 < this.ordering.size(); i2++) {
                if (((Boolean) this.added.elementAt(i2)).booleanValue()) {
                    vector.insertElementAt(this.ordering.elementAt(i2), i);
                    vector2.insertElementAt(this.values.elementAt(i2), i);
                    vector3.insertElementAt(this.added.elementAt(i2), i);
                    i++;
                } else {
                    vector.insertElementAt(this.ordering.elementAt(i2), 0);
                    vector2.insertElementAt(this.values.elementAt(i2), 0);
                    vector3.insertElementAt(this.added.elementAt(i2), 0);
                    i = 1;
                }
            }
            this.ordering = vector;
            this.values = vector2;
            this.added = vector3;
        }
    }

    private void addEntry(Hashtable hashtable, String str, Boolean bool) {
        X509NameTokenizer x509NameTokenizer = new X509NameTokenizer(str, '=');
        String nextToken = x509NameTokenizer.nextToken();
        if (x509NameTokenizer.hasMoreTokens()) {
            String nextToken2 = x509NameTokenizer.nextToken();
            this.ordering.addElement(decodeOID(nextToken, hashtable));
            this.values.addElement(unescape(nextToken2));
            this.added.addElement(bool);
            return;
        }
        throw new IllegalArgumentException("badly formatted directory string");
    }

    private void appendValue(StringBuffer stringBuffer, Hashtable hashtable, ASN1ObjectIdentifier aSN1ObjectIdentifier, String str) {
        String str2 = (String) hashtable.get(aSN1ObjectIdentifier);
        if (str2 != null) {
            stringBuffer.append(str2);
        } else {
            stringBuffer.append(aSN1ObjectIdentifier.getId());
        }
        stringBuffer.append('=');
        int length = stringBuffer.length();
        stringBuffer.append(str);
        int length2 = stringBuffer.length();
        int i = (str.length() >= 2 && str.charAt(0) == '\\' && str.charAt(1) == '#') ? length + 2 : length;
        while (i != length2) {
            if (stringBuffer.charAt(i) == ',' || stringBuffer.charAt(i) == '\"' || stringBuffer.charAt(i) == '\\' || stringBuffer.charAt(i) == '+' || stringBuffer.charAt(i) == '=' || stringBuffer.charAt(i) == '<' || stringBuffer.charAt(i) == '>' || stringBuffer.charAt(i) == ';') {
                stringBuffer.insert(i, "\\");
                i++;
                length2++;
            }
            i++;
        }
        for (length2 = length; stringBuffer.charAt(length2) == ' '; length2 += 2) {
            stringBuffer.insert(length2, "\\");
        }
        length2 = stringBuffer.length() - 1;
        while (length2 >= 0 && stringBuffer.charAt(length2) == ' ') {
            stringBuffer.insert(length2, '\\');
            length2--;
        }
    }

    private String bytesToString(byte[] bArr) {
        char[] cArr = new char[bArr.length];
        for (int i = 0; i != cArr.length; i++) {
            cArr[i] = (char) (bArr[i] & 255);
        }
        return new String(cArr);
    }

    private String canonicalize(String str) {
        String toLowerCase = Strings.toLowerCase(str.trim());
        if (toLowerCase.length() > 0 && toLowerCase.charAt(0) == '#') {
            ASN1Primitive decodeObject = decodeObject(toLowerCase);
            if (decodeObject instanceof ASN1String) {
                return Strings.toLowerCase(((ASN1String) decodeObject).getString().trim());
            }
        }
        return toLowerCase;
    }

    private ASN1ObjectIdentifier decodeOID(String str, Hashtable hashtable) {
        String trim = str.trim();
        if (Strings.toUpperCase(trim).startsWith("OID.")) {
            return new ASN1ObjectIdentifier(trim.substring(4));
        }
        if (trim.charAt(0) >= '0' && trim.charAt(0) <= '9') {
            return new ASN1ObjectIdentifier(trim);
        }
        ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) hashtable.get(Strings.toLowerCase(trim));
        if (aSN1ObjectIdentifier != null) {
            return aSN1ObjectIdentifier;
        }
        throw new IllegalArgumentException("Unknown object id - " + trim + " - passed to distinguished name");
    }

    private ASN1Primitive decodeObject(String str) {
        try {
            return ASN1Primitive.fromByteArray(Hex.decode(str.substring(1)));
        } catch (IOException e) {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }

    private boolean equivalentStrings(String str, String str2) {
        String canonicalize = canonicalize(str);
        String canonicalize2 = canonicalize(str2);
        return canonicalize.equals(canonicalize2) || stripInternalSpaces(canonicalize).equals(stripInternalSpaces(canonicalize2));
    }

    public static X509Name getInstance(Object obj) {
        return (obj == null || (obj instanceof X509Name)) ? (X509Name) obj : obj instanceof X500Name ? new X509Name(ASN1Sequence.getInstance(((X500Name) obj).toASN1Primitive())) : obj != null ? new X509Name(ASN1Sequence.getInstance(obj)) : null;
    }

    public static X509Name getInstance(ASN1TaggedObject aSN1TaggedObject, boolean z) {
        return getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, z));
    }

    private String stripInternalSpaces(String str) {
        StringBuffer stringBuffer = new StringBuffer();
        if (str.length() != 0) {
            char charAt = str.charAt(0);
            stringBuffer.append(charAt);
            int i = 1;
            while (i < str.length()) {
                char charAt2 = str.charAt(i);
                if (charAt != ' ' || charAt2 != ' ') {
                    stringBuffer.append(charAt2);
                }
                i++;
                charAt = charAt2;
            }
        }
        return stringBuffer.toString();
    }

    private String unescape(String str) {
        if (str.length() == 0 || (str.indexOf(92) < 0 && str.indexOf(34) < 0)) {
            return str.trim();
        }
        int i;
        char[] toCharArray = str.toCharArray();
        StringBuffer stringBuffer = new StringBuffer(str.length());
        if (toCharArray[0] == '\\' && toCharArray[1] == '#') {
            i = 2;
            stringBuffer.append("\\#");
        } else {
            i = 0;
        }
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        for (i = 
/*
Method generation error in method: org.bouncycastle.asn1.x509.X509Name.unescape(java.lang.String):java.lang.String, dex: classes.dex
jadx.core.utils.exceptions.CodegenException: Error generate insn: PHI: (r0_7 'i' int) = (r0_6 'i' int), (r0_19 'i' int) binds: {(r0_19 'i' int)=B:42:0x0099, (r0_6 'i' int)=B:11:0x0036} in method: org.bouncycastle.asn1.x509.X509Name.unescape(java.lang.String):java.lang.String, dex: classes.dex
	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:226)
	at jadx.core.codegen.RegionGen.makeLoop(RegionGen.java:184)
	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:61)
	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:87)
	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:53)
	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:87)
	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:53)
	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:87)
	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:53)
	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:187)
	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:320)
	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:257)
	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:220)
	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:110)
	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
	at jadx.core.codegen.CodeGen.visit(CodeGen.java:12)
	at jadx.core.ProcessClass.process(ProcessClass.java:40)
	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:282)
	at jadx.api.JavaClass.decompile(JavaClass.java:62)
	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:200)
	at jadx.api.JadxDecompiler$$Lambda$8/1122805102.run(Unknown Source)
Caused by: jadx.core.utils.exceptions.CodegenException: PHI can be used only in fallback mode
	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:537)
	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:509)
	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:220)
	... 20 more

*/

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof X509Name) && !(obj instanceof ASN1Sequence)) {
                return false;
            }
            if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
                return true;
            }
            try {
                X509Name instance = getInstance(obj);
                int size = this.ordering.size();
                if (size != instance.ordering.size()) {
                    return false;
                }
                int i;
                int i2;
                int i3;
                boolean[] zArr = new boolean[size];
                if (this.ordering.elementAt(0).equals(instance.ordering.elementAt(0))) {
                    i = 1;
                    i2 = size;
                    i3 = 0;
                } else {
                    i3 = size - 1;
                    i = -1;
                    i2 = -1;
                }
                for (int i4 = i3; i4 != i2; i4 += i) {
                    boolean z;
                    ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier) this.ordering.elementAt(i4);
                    String str = (String) this.values.elementAt(i4);
                    int i5 = 0;
                    while (i5 < size) {
                        if (!zArr[i5] && aSN1ObjectIdentifier.equals((ASN1ObjectIdentifier) instance.ordering.elementAt(i5)) && equivalentStrings(str, (String) instance.values.elementAt(i5))) {
                            zArr[i5] = true;
                            z = true;
                            break;
                        }
                        i5++;
                    }
                    z = false;
                    if (!z) {
                        return false;
                    }
                }
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }

        public boolean equals(Object obj, boolean z) {
            if (!z) {
                return equals(obj);
            }
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof X509Name) && !(obj instanceof ASN1Sequence)) {
                return false;
            }
            if (toASN1Primitive().equals(((ASN1Encodable) obj).toASN1Primitive())) {
                return true;
            }
            try {
                X509Name instance = getInstance(obj);
                int size = this.ordering.size();
                if (size != instance.ordering.size()) {
                    return false;
                }
                for (int i = 0; i < size; i++) {
                    if (!((ASN1ObjectIdentifier) this.ordering.elementAt(i)).equals((ASN1ObjectIdentifier) instance.ordering.elementAt(i))) {
                        return false;
                    }
                    if (!equivalentStrings((String) this.values.elementAt(i), (String) instance.values.elementAt(i))) {
                        return false;
                    }
                }
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }

        public Vector getOIDs() {
            Vector vector = new Vector();
            for (int i = 0; i != this.ordering.size(); i++) {
                vector.addElement(this.ordering.elementAt(i));
            }
            return vector;
        }

        public Vector getValues() {
            Vector vector = new Vector();
            for (int i = 0; i != this.values.size(); i++) {
                vector.addElement(this.values.elementAt(i));
            }
            return vector;
        }

        public Vector getValues(ASN1ObjectIdentifier aSN1ObjectIdentifier) {
            Vector vector = new Vector();
            for (int i = 0; i != this.values.size(); i++) {
                if (this.ordering.elementAt(i).equals(aSN1ObjectIdentifier)) {
                    String str = (String) this.values.elementAt(i);
                    if (str.length() > 2 && str.charAt(0) == '\\' && str.charAt(1) == '#') {
                        vector.addElement(str.substring(1));
                    } else {
                        vector.addElement(str);
                    }
                }
            }
            return vector;
        }

        public int hashCode() {
            if (this.isHashCodeCalculated) {
                return this.hashCodeValue;
            }
            this.isHashCodeCalculated = true;
            for (int i = 0; i != this.ordering.size(); i++) {
                String stripInternalSpaces = stripInternalSpaces(canonicalize((String) this.values.elementAt(i)));
                this.hashCodeValue ^= this.ordering.elementAt(i).hashCode();
                this.hashCodeValue = stripInternalSpaces.hashCode() ^ this.hashCodeValue;
            }
            return this.hashCodeValue;
        }

        public ASN1Primitive toASN1Primitive() {
            if (this.seq == null) {
                ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
                ASN1ObjectIdentifier aSN1ObjectIdentifier = null;
                ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
                int i = 0;
                while (i != this.ordering.size()) {
                    ASN1EncodableVector aSN1EncodableVector3;
                    ASN1EncodableVector aSN1EncodableVector4 = new ASN1EncodableVector();
                    ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier) this.ordering.elementAt(i);
                    aSN1EncodableVector4.add(aSN1ObjectIdentifier2);
                    aSN1EncodableVector4.add(this.converter.getConvertedValue(aSN1ObjectIdentifier2, (String) this.values.elementAt(i)));
                    if (aSN1ObjectIdentifier == null || ((Boolean) this.added.elementAt(i)).booleanValue()) {
                        aSN1EncodableVector2.add(new DERSequence(aSN1EncodableVector4));
                        aSN1EncodableVector3 = aSN1EncodableVector2;
                    } else {
                        aSN1EncodableVector.add(new DERSet(aSN1EncodableVector2));
                        aSN1EncodableVector3 = new ASN1EncodableVector();
                        aSN1EncodableVector3.add(new DERSequence(aSN1EncodableVector4));
                    }
                    i++;
                    aSN1EncodableVector2 = aSN1EncodableVector3;
                    aSN1ObjectIdentifier = aSN1ObjectIdentifier2;
                }
                aSN1EncodableVector.add(new DERSet(aSN1EncodableVector2));
                this.seq = new DERSequence(aSN1EncodableVector);
            }
            return this.seq;
        }

        public String toString() {
            return toString(DefaultReverse, DefaultSymbols);
        }

        public String toString(boolean z, Hashtable hashtable) {
            StringBuffer stringBuffer = new StringBuffer();
            Vector vector = new Vector();
            StringBuffer stringBuffer2 = null;
            int i = 0;
            while (i < this.ordering.size()) {
                StringBuffer stringBuffer3;
                if (((Boolean) this.added.elementAt(i)).booleanValue()) {
                    stringBuffer2.append('+');
                    appendValue(stringBuffer2, hashtable, (ASN1ObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
                    stringBuffer3 = stringBuffer2;
                } else {
                    stringBuffer2 = new StringBuffer();
                    appendValue(stringBuffer2, hashtable, (ASN1ObjectIdentifier) this.ordering.elementAt(i), (String) this.values.elementAt(i));
                    vector.addElement(stringBuffer2);
                    stringBuffer3 = stringBuffer2;
                }
                i++;
                stringBuffer2 = stringBuffer3;
            }
            if (z) {
                Object obj = 1;
                for (int size = vector.size() - 1; size >= 0; size--) {
                    if (obj != null) {
                        obj = null;
                    } else {
                        stringBuffer.append(',');
                    }
                    stringBuffer.append(vector.elementAt(size).toString());
                }
            } else {
                Object obj2 = 1;
                for (int i2 = 0; i2 < vector.size(); i2++) {
                    if (obj2 != null) {
                        obj2 = null;
                    } else {
                        stringBuffer.append(',');
                    }
                    stringBuffer.append(vector.elementAt(i2).toString());
                }
            }
            return stringBuffer.toString();
        }
    }

package custom.org.apache.harmony.security.utils;

import custom.org.apache.harmony.security.Util;
import custom.org.apache.harmony.security.asn1.ObjectIdentifier;
import es.gob.jmulticard.jse.provider.DnieProvider;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public class AlgNameMapper {
    private static final Map<String, String> alg2OidMap = new HashMap();
    private static final Map<String, String> algAliasesMap = new HashMap();
    private static final String[][] knownAlgMappings;
    private static final Map<String, String> oid2AlgMap = new HashMap();
    private static final String[] serviceName = new String[]{"Cipher", "AlgorithmParameters", "Signature"};

    static {
        r6 = new String[20][];
        r6[0] = new String[]{"1.2.840.10040.4.1", "DSA"};
        r6[1] = new String[]{"1.2.840.10040.4.3", "SHA1withDSA"};
        r6[2] = new String[]{"1.2.840.113549.1.1.1", "RSA"};
        r6[3] = new String[]{"1.2.840.113549.1.1.2", "MD2withRSA"};
        r6[4] = new String[]{"1.2.840.113549.1.1.4", "MD5withRSA"};
        r6[5] = new String[]{"1.2.840.113549.1.1.5", DnieProvider.SHA1WITH_RSA};
        r6[6] = new String[]{"1.2.840.113549.1.3.1", "DiffieHellman"};
        r6[7] = new String[]{"1.2.840.113549.1.5.3", "pbeWithMD5AndDES-CBC"};
        r6[8] = new String[]{"1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC"};
        r6[9] = new String[]{"1.2.840.113549.1.12.1.6", "pbeWithSHAAnd40BitRC2-CBC"};
        r6[10] = new String[]{"1.2.840.113549.3.2", "RC2-CBC"};
        r6[11] = new String[]{"1.2.840.113549.3.3", "RC2-EBC"};
        r6[12] = new String[]{"1.2.840.113549.3.4", "RC4"};
        r6[13] = new String[]{"1.2.840.113549.3.5", "RC4WithMAC"};
        r6[14] = new String[]{"1.2.840.113549.3.6", "DESx-CBC"};
        r6[15] = new String[]{"1.2.840.113549.3.7", "TripleDES-CBC"};
        r6[16] = new String[]{"1.2.840.113549.3.8", "rc5CBC"};
        r6[17] = new String[]{"1.2.840.113549.3.9", "RC5-CBC"};
        r6[18] = new String[]{"1.2.840.113549.3.10", "DESCDMF"};
        r6[19] = new String[]{"2.23.42.9.11.4.1", "ECDSA"};
        knownAlgMappings = r6;
        for (String[] element : knownAlgMappings) {
            String algUC = Util.toUpperCase(element[1]);
            alg2OidMap.put(algUC, element[0]);
            oid2AlgMap.put(element[0], algUC);
            algAliasesMap.put(algUC, element[1]);
        }
        for (Provider element2 : Security.getProviders()) {
            selectEntries(element2);
        }
    }

    private AlgNameMapper() {
    }

    public static String map2OID(String algName) {
        return (String) alg2OidMap.get(Util.toUpperCase(algName));
    }

    public static String map2AlgName(String oid) {
        String algUC = (String) oid2AlgMap.get(oid);
        return algUC == null ? null : (String) algAliasesMap.get(algUC);
    }

    public static String getStandardName(String algName) {
        return (String) algAliasesMap.get(Util.toUpperCase(algName));
    }

    private static void selectEntries(Provider p) {
        Set<Entry<Object, Object>> entrySet = p.entrySet();
        for (String service : serviceName) {
            String keyPrfix2find = "Alg.Alias." + service + ".";
            for (Entry<Object, Object> me : entrySet) {
                String key = (String) me.getKey();
                if (key.startsWith(keyPrfix2find)) {
                    String alias = key.substring(keyPrfix2find.length());
                    String alg = (String) me.getValue();
                    String algUC = Util.toUpperCase(alg);
                    if (isOID(alias)) {
                        if (alias.startsWith("OID.")) {
                            alias = alias.substring(4);
                        }
                        boolean oid2AlgContains = oid2AlgMap.containsKey(alias);
                        boolean alg2OidContains = alg2OidMap.containsKey(algUC);
                        if (!oid2AlgContains || !alg2OidContains) {
                            if (!oid2AlgContains) {
                                oid2AlgMap.put(alias, algUC);
                            }
                            if (!alg2OidContains) {
                                alg2OidMap.put(algUC, alias);
                            }
                            algAliasesMap.put(algUC, alg);
                        }
                    } else if (!algAliasesMap.containsKey(Util.toUpperCase(alias))) {
                        algAliasesMap.put(Util.toUpperCase(alias), alg);
                    }
                }
            }
        }
    }

    public static boolean isOID(String alias) {
        try {
            ObjectIdentifier.toIntArray(normalize(alias));
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static String normalize(String oid) {
        return oid.startsWith("OID.") ? oid.substring(4) : oid;
    }

    public static String dump() {
        StringBuilder sb = new StringBuilder("alg2OidMap: ");
        sb.append(alg2OidMap);
        sb.append("\noid2AlgMap: ");
        sb.append(oid2AlgMap);
        sb.append("\nalgAliasesMap: ");
        sb.append(algAliasesMap);
        return sb.toString();
    }
}

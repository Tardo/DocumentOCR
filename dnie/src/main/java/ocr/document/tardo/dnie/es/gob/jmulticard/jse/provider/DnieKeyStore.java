package es.gob.jmulticard.jse.provider;

import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG13;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

public class DnieKeyStore extends KeyStore {
    private static final List<String> USERS_DATA_LABELS = new ArrayList(3);
    private static KeyStore ks;
    private static KeyStoreSpi ksSpi;

    static {
        USERS_DATA_LABELS.add("ADMIN_ImagenFacial");
        USERS_DATA_LABELS.add("ADMIN_ImagenFirma");
        USERS_DATA_LABELS.add("ADMIN_DatosFiliacion");
    }

    public DnieKeyStore(KeyStoreSpi keyStoreSpi, Provider provider, String type) {
        super(keyStoreSpi, provider, type);
        ksSpi = keyStoreSpi;
    }

    public void setKeyStore(KeyStore k) {
        ks = k;
    }

    public KeyStore getKeyStore() {
        return ks;
    }

    public EF_COM getEFCOM() {
        return ((MrtdKeyStoreImpl) ksSpi).getEFCOM();
    }

    public DG1_Dnie getDatagroup1() {
        return ((MrtdKeyStoreImpl) ksSpi).getDataGroup1();
    }

    public DG11 getDatagroup11() {
        return ((MrtdKeyStoreImpl) ksSpi).getDataGroup11();
    }

    public DG13 getDatagroup13() {
        return ((MrtdKeyStoreImpl) ksSpi).getDataGroup13();
    }

    public DG2 getDatagroup2() {
        return ((MrtdKeyStoreImpl) ksSpi).getDataGroup2();
    }

    public DG7 getDatagroup7() {
        return ((MrtdKeyStoreImpl) ksSpi).getDataGroup7();
    }

    public byte[] getDataObject(String label) {
        if (containsLabels(label)) {
            return ((MrtdKeyStoreImpl) ksSpi).getDataObject(label);
        }
        return null;
    }

    public static boolean containsLabels(String alias) {
        return USERS_DATA_LABELS.contains(alias);
    }
}

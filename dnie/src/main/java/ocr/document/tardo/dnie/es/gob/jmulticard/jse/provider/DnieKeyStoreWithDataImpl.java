package es.gob.jmulticard.jse.provider;

import android.nfc.Tag;
import es.gob.jmulticard.card.AuthenticationModeLockedException;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.dnie.Dnie;
import es.gob.jmulticard.card.dnie.DniePrivateKeyReference;
import es.gob.jmulticard.jse.smartcardio.SmartCardNFCConnection;
import es.gob.jmulticard.jse.smartcardio.SmartcardIoConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore.Entry;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

public final class DnieKeyStoreWithDataImpl extends KeyStoreSpi {
    private static final String INTERMEDIATE_CA_CERT_ALIAS = "CertCAIntermediaDGP";
    private static final List<String> USERS_CERTS_ALIASES = new ArrayList(2);
    private static final List<String> USERS_DATA_LABELS = new ArrayList(3);
    private CryptoCard cryptoCard = null;

    static {
        USERS_CERTS_ALIASES.add("CertAutenticacion");
        USERS_CERTS_ALIASES.add("CertFirmaDigital");
        USERS_DATA_LABELS.add("ADMIN_ImagenFacial");
        USERS_DATA_LABELS.add("ADMIN_ImagenFirma");
        USERS_DATA_LABELS.add("ADMIN_DatosFiliacion");
    }

    public Enumeration<String> engineAliases() {
        return Collections.enumeration(USERS_CERTS_ALIASES);
    }

    public boolean engineContainsAlias(String alias) {
        return USERS_CERTS_ALIASES.contains(alias);
    }

    public void engineDeleteEntry(String alias) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    public Certificate engineGetCertificate(String alias) {
        if (!engineContainsAlias(alias)) {
            return null;
        }
        try {
            return this.cryptoCard.getCertificate(alias);
        } catch (CryptoCardException e) {
            throw new ProviderException(e.getMessage());
        }
    }

    public String engineGetCertificateAlias(Certificate cert) {
        if (!(cert instanceof X509Certificate)) {
            return null;
        }
        BigInteger serial = ((X509Certificate) cert).getSerialNumber();
        for (String alias : USERS_CERTS_ALIASES) {
            if (((X509Certificate) engineGetCertificate(alias)).getSerialNumber() == serial) {
                return alias;
            }
        }
        return null;
    }

    public Certificate[] engineGetCertificateChain(String alias) {
        if (!engineContainsAlias(alias)) {
            return null;
        }
        X509Certificate intermediateCaCert;
        try {
            intermediateCaCert = this.cryptoCard.getCertificate(INTERMEDIATE_CA_CERT_ALIAS);
        } catch (AuthenticationModeLockedException e) {
            throw e;
        } catch (Exception e2) {
            Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el certificado de la CA intermedia");
            intermediateCaCert = null;
        }
        if (intermediateCaCert == null) {
            return new X509Certificate[]{(X509Certificate) engineGetCertificate(alias)};
        }
        return new X509Certificate[]{(X509Certificate) engineGetCertificate(alias), intermediateCaCert};
    }

    public Date engineGetCreationDate(String alias) {
        throw new UnsupportedOperationException();
    }

    public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
        if (password != null) {
            Logger.getLogger("es.gob.jmulticard").warning("Se ha proporcionado una contrasena, pero esta se ignorara, ya que el PIN se gestiona internamente");
        }
        if (!engineContainsAlias(alias)) {
            return null;
        }
        try {
            PrivateKeyReference pkRef = this.cryptoCard.getPrivateKey(alias);
            if (pkRef instanceof DniePrivateKeyReference) {
                return new DniePrivateKey((DniePrivateKeyReference) pkRef);
            }
            throw new ProviderException("La clave obtenida de la tarjeta no es del tipo esperado, se ha obtenido: " + pkRef.getClass().getName());
        } catch (CryptoCardException e) {
            throw new ProviderException(e.getMessage());
        }
    }

    public Entry engineGetEntry(String alias, ProtectionParameter protParam) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        if (protParam != null) {
            Logger.getLogger("es.gob.jmulticard").warning("Se ha proporcionado un ProtectionParameter, pero este se ignorara, ya que el PIN se gestiona internamente");
        }
        if (engineContainsAlias(alias)) {
            return new PrivateKeyEntry((PrivateKey) engineGetKey(alias, null), engineGetCertificateChain(alias));
        }
        return null;
    }

    public boolean engineIsCertificateEntry(String alias) {
        return USERS_CERTS_ALIASES.contains(alias);
    }

    public boolean engineIsKeyEntry(String alias) {
        return USERS_CERTS_ALIASES.contains(alias);
    }

    public void engineLoad(LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (param != null) {
            throw new IllegalArgumentException("El LoadStoreParameter siempre debe ser null, la contrasena se gestiona internamente");
        }
        Tag tagNFC = ((DnieProvider) Security.getProvider("DNIeJCAProvider")).getProviderTag();
        this.cryptoCard = new Dnie(tagNFC != null ? new SmartCardNFCConnection(tagNFC) : new SmartcardIoConnection(), null, new JseCryptoHelper());
    }

    public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        if (password != null) {
            throw new IllegalArgumentException("La contrasena siempre debe ser null, esta se gestiona internamente");
        }
        Tag tagNFC = ((DnieProvider) Security.getProvider("DNIeJCAProvider")).getProviderTag();
        this.cryptoCard = new Dnie(tagNFC != null ? new SmartCardNFCConnection(tagNFC) : new SmartcardIoConnection(), null, new JseCryptoHelper());
    }

    public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    public void engineSetKeyEntry(String alias, Key key, char[] pass, Certificate[] chain) throws KeyStoreException {
        throw new UnsupportedOperationException();
    }

    public int engineSize() {
        return USERS_CERTS_ALIASES.size();
    }

    public void engineStore(OutputStream os, char[] pass) throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new UnsupportedOperationException();
    }

    public boolean engineEntryInstanceOf(String alias, Class<? extends Entry> entryClass) {
        if (engineContainsAlias(alias)) {
            return entryClass.equals(PrivateKeyEntry.class);
        }
        return false;
    }

    public byte[] getDataObject(String label) {
        if (!containsLabels(label)) {
            return null;
        }
        try {
            return this.cryptoCard.getDataObject(label);
        } catch (CryptoCardException e) {
            throw new ProviderException(e.getMessage());
        }
    }

    public boolean containsLabels(String alias) {
        return USERS_DATA_LABELS.contains(alias);
    }
}

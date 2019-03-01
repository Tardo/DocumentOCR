package es.gob.jmulticard.card.dnie;

import android.nfc.Tag;
import com.jcraft.jzlib.Inflater;
import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG13;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.HexUtils;
import es.gob.jmulticard.apdu.ResponseApdu;
import es.gob.jmulticard.apdu.connection.ApduConnection;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.CardNotPresentException;
import es.gob.jmulticard.apdu.connection.LostChannelException;
import es.gob.jmulticard.apdu.connection.NoReadersFoundException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneConnection;
import es.gob.jmulticard.apdu.connection.cwa14890.InvalidCryptographicChecksum;
import es.gob.jmulticard.apdu.connection.cwa14890.SecureChannelException;
import es.gob.jmulticard.apdu.dnie.GetChipInfoApduCommand;
import es.gob.jmulticard.apdu.iso7816eight.PsoSignHashApduCommand;
import es.gob.jmulticard.apdu.iso7816four.ExternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.InternalAuthenticateApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetAuthenticationKeyApduCommand;
import es.gob.jmulticard.apdu.iso7816four.MseSetSignatureKeyApduCommand;
import es.gob.jmulticard.asn1.Asn1Exception;
import es.gob.jmulticard.asn1.TlvException;
import es.gob.jmulticard.asn1.der.pkcs1.DigestInfo;
import es.gob.jmulticard.asn1.der.pkcs15.Cdf;
import es.gob.jmulticard.asn1.der.pkcs15.Dodf;
import es.gob.jmulticard.asn1.der.pkcs15.PrKdf;
import es.gob.jmulticard.card.Atr;
import es.gob.jmulticard.card.CryptoCard;
import es.gob.jmulticard.card.CryptoCardException;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.Location;
import es.gob.jmulticard.card.PrivateKeyReference;
import es.gob.jmulticard.card.cwa14890.Cwa14890Card;
import es.gob.jmulticard.card.iso7816eight.Iso7816EightCard;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.jse.smartcardio.SmartCardNFCConnection;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import javax.security.auth.callback.PasswordCallback;

public final class Dnie extends Iso7816EightCard implements CryptoCard, Cwa14890Card {
    private static final Atr ATR = new Atr(new byte[]{(byte) 59, Byte.MAX_VALUE, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 106, (byte) 68, (byte) 78, (byte) 73, (byte) 101, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -112, (byte) 0}, ATR_MASK);
    private static final byte[] ATR_MASK = new byte[]{(byte) -1, (byte) -1, (byte) 0, (byte) -1, (byte) -1, (byte) -1, (byte) -1, (byte) -1, (byte) -1, (byte) -1, (byte) -1, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) -1, (byte) -1};
    private static final String AUTHENTICATION_CONFIRMATION_PROPERTY = "es.gob.jmulticard.authConfirmation";
    private static final String AUTH_CERT_ALIAS = "CertAutenticacion";
    private static final String AUTH_KEY_LABEL = "KprivAutenticacion";
    private static final Atr BURNED_DNI_ATR = new Atr(new byte[]{(byte) 59, Byte.MAX_VALUE, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 106, (byte) 68, (byte) 78, (byte) 73, (byte) 101, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 101, (byte) -127}, ATR_MASK);
    private static final Location CDF_LOCATION = new Location("50156004");
    private static final byte[] CERT_ICC_FILE_ID = new byte[]{(byte) 96, (byte) 31};
    private static final String DATA_LABEL_FILI = "ADMIN_DatosFiliacion";
    private static final String DATA_LABEL_FIRMA = "ADMIN_ImagenFirma";
    private static final String DATA_LABEL_FOTO = "ADMIN_ImagenFacial";
    private static final Location DODF_LOCATION = new Location("50156005");
    private static final String FAST_MODE_PROPERTY = "es.gob.jmulticard.fastmode";
    private static final String INTERMEDIATE_CA_CERT_ALIAS = "CertCAIntermediaDGP";
    private static final String MASTER_FILE_NAME = "Master.File";
    private static final Location PRKDF_LOCATION = new Location("50156001");
    private static final String SIGN_CERT_ALIAS = "CertFirmaDigital";
    private static final String SIGN_KEY_LABEL = "KprivFirmaDigital";
    private X509Certificate authCert;
    private Location authCertPath;
    private DniePrivateKeyReference authKeyRef;
    private CryptoHelper cryptoHelper = null;
    private final boolean fastMode;
    private byte[] filiData;
    private Location filiDataPath;
    private byte[] firmaData;
    private Location firmaDataPath;
    private byte[] fotoData;
    private Location fotoDataPath;
    private X509Certificate intermediateCaCert;
    public short m_SW;
    boolean m_secureChannel;
    public Tag mtag;
    private boolean needsRealCertificates = false;
    private final PasswordCallback passwordCallback;
    List<byte[]> prKDFentryCDF = new ArrayList();
    List<String> prKDFentryTtl = new ArrayList();
    List<byte[]> prKDFentrybts = new ArrayList();
    private byte[] serialID;
    private X509Certificate signCert;
    private Location signCertPath;
    private DniePrivateKeyReference signKeyRef;

    private void connect(ApduConnection conn) throws BurnedDnieCardException, InvalidCardException, ApduConnectionException {
        if (conn == null) {
            throw new IllegalArgumentException("La conexion no puede ser nula");
        } else if (!(conn instanceof SmartCardNFCConnection)) {
            InvalidCardException invalidCardException = null;
            CardNotPresentException cardNotPresentException = null;
            long[] terminals = conn.getTerminals(false);
            if (terminals.length < 1) {
                throw new NoReadersFoundException();
            }
            int i = 0;
            while (i < terminals.length) {
                conn.setTerminal((int) terminals[i]);
                try {
                    byte[] responseAtr = conn.reset();
                    Atr actualAtr = new Atr(responseAtr, ATR_MASK);
                    if (BURNED_DNI_ATR.equals(actualAtr)) {
                        throw new BurnedDnieCardException();
                    } else if (!ATR.equals(actualAtr)) {
                        invalidCardException = new InvalidCardException(getCardName(), ATR, responseAtr);
                        i++;
                    } else {
                        return;
                    }
                } catch (CardNotPresentException e) {
                    cardNotPresentException = e;
                }
            }
            if (invalidCardException != null) {
                throw invalidCardException;
            } else if (cardNotPresentException != null) {
                throw cardNotPresentException;
            } else {
                throw new ApduConnectionException("No se ha podido conectar con ningun lector de tarjetas");
            }
        }
    }

    public Dnie(ApduConnection conn, PasswordCallback pwc, CryptoHelper cryptoHelper) throws ApduConnectionException, InvalidCardException, BurnedDnieCardException {
        super((byte) 0, conn);
        connect(conn);
        this.passwordCallback = pwc;
        if (cryptoHelper == null) {
            throw new IllegalArgumentException("El CryptoHelper no puede ser nula");
        }
        this.cryptoHelper = cryptoHelper;
        this.fastMode = Boolean.getBoolean(FAST_MODE_PROPERTY);
        preloadCertificates();
        loadKeyReferences();
    }

    private void loadKeyReferences() {
        PrKdf prKdf = new PrKdf();
        try {
            prKdf.setDerValue(selectFileByLocationAndRead(PRKDF_LOCATION));
            for (int i = 0; i < prKdf.getKeyCount(); i++) {
                if (AUTH_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                    this.authKeyRef = new DniePrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), AUTH_KEY_LABEL);
                } else if (SIGN_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                    this.signKeyRef = new DniePrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), SIGN_KEY_LABEL);
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("No se ha podido cargar el PrKDF de la tarjeta: " + e.getMessage());
        }
    }

    public byte[] getSerialNumber() throws ApduConnectionException {
        boolean z = true;
        try {
            ResponseApdu response = getConnection().transmit(new GetChipInfoApduCommand());
            if (response.isOk()) {
                return response.getData();
            }
            throw new ApduConnectionException("Respuesta invalida en la obtencion del numero de serie con el codigo: " + response.getStatusWord());
        } catch (LostChannelException e) {
            try {
                if (this.fastMode) {
                    z = false;
                }
                this.needsRealCertificates = z;
                getConnection().close();
                if (getConnection() instanceof Cwa14890OneConnection) {
                    setConnection(((Cwa14890OneConnection) getConnection()).getSubConnection());
                }
                return getSerialNumber();
            } catch (Exception ex) {
                throw new ApduConnectionException("No se pudo recuperar el canal seguro " + ex.getMessage(), ex);
            }
        } catch (InvalidCryptographicChecksum e2) {
            try {
                getConnection().close();
                if (this.fastMode) {
                    z = false;
                }
                this.needsRealCertificates = z;
                if (getConnection() instanceof Cwa14890OneConnection) {
                    setConnection(((Cwa14890OneConnection) getConnection()).getSubConnection());
                }
                return getSerialNumber();
            } catch (Exception ex2) {
                throw new ApduConnectionException("Error reestableciendo el canal de comunicacion", ex2);
            }
        } catch (IOException ex3) {
            ex3.printStackTrace();
            throw new ApduConnectionException("Error de conexión con la tarjeta DNIe", ex3);
        }
    }

    public String getCardName() {
        return "DNIe";
    }

    public String[] getAliases() {
        return new String[]{AUTH_CERT_ALIAS, SIGN_CERT_ALIAS};
    }

    private void preloadCertificates() {
        try {
            this.serialID = getSerialNumber();
            Cdf cdf = new Cdf();
            try {
                selectMasterFile();
                cdf.setDerValue(selectFileByLocationAndRead(CDF_LOCATION));
            } catch (Asn1Exception e) {
                Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el CDF de la tarjeta: " + e.getMessage());
            } catch (TlvException e2) {
                Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el CDF de la tarjeta: " + e2.getMessage());
            } catch (Exception e3) {
                throw new IllegalStateException("No se ha podido cargar el CDF de la tarjeta: " + e3.getMessage());
            }
            for (int i = 0; i < cdf.getCertificateCount(); i++) {
                X509Certificate tmpCert = new FakeX509Certificate(cdf.getCertificateSubjectPrincipal(i), cdf.getCertificateIssuerPrincipal(i), cdf.getCertificateSerialNumber(i), AUTH_CERT_ALIAS.equals(cdf.getCertificateAlias(i)));
                if (AUTH_CERT_ALIAS.equals(cdf.getCertificateAlias(i))) {
                    this.authCert = tmpCert;
                    this.authCertPath = new Location(cdf.getCertificatePath(i));
                } else if (SIGN_CERT_ALIAS.equals(cdf.getCertificateAlias(i))) {
                    this.signCert = tmpCert;
                    this.signCertPath = new Location(cdf.getCertificatePath(i));
                } else {
                    try {
                        this.intermediateCaCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(deflate(selectFileByLocationAndRead(new Location(cdf.getCertificatePath(i))))));
                    } catch (Exception e32) {
                        Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el certificado de la autoridad intermedia de la DGP: " + e32.toString());
                        this.intermediateCaCert = null;
                    }
                }
            }
        } catch (Exception e322) {
            Logger.getLogger("es.gob.jmulticard").warning("No se ha podido obtener el ID de la tarjeta");
            throw new IllegalStateException(e322.getMessage());
        }
    }

    private void loadCertificates() throws CryptoCardException {
        if (!isSecurityChannelOpen()) {
            verifyAndLoadCertificates();
        }
    }

    public X509Certificate getCertificate(String alias) throws CryptoCardException {
        try {
            if (!HexUtils.arrayEquals(getSerialNumber(), this.serialID)) {
                preloadCertificates();
                loadKeyReferences();
            }
            if (this.needsRealCertificates || ((this.authCert instanceof FakeX509Certificate) && !this.fastMode)) {
                loadCertificates();
            }
            if (AUTH_CERT_ALIAS.equals(alias)) {
                return this.authCert;
            }
            if (SIGN_CERT_ALIAS.equals(alias)) {
                return this.signCert;
            }
            if (INTERMEDIATE_CA_CERT_ALIAS.equals(alias)) {
                return this.intermediateCaCert;
            }
            return null;
        } catch (ApduConnectionException e) {
            throw new CryptoCardException(e.getMessage());
        }
    }

    public void verifyCaIntermediateIcc() throws CertificateException, IOException {
    }

    public void verifyIcc() throws CertificateException, IOException {
    }

    public byte[] getIccCertEncoded() throws IOException {
        try {
            return selectFileByIdAndRead(CERT_ICC_FILE_ID);
        } catch (ApduConnectionException e) {
            throw new IOException("Error en el envio de APDU para la seleccion del certificado de componente de la tarjeta: " + e);
        } catch (Iso7816FourCardException e2) {
            throw new IOException("Error en la seleccion del certificado de componente de la tarjeta: " + e2);
        }
    }

    public void verifyIfdCertificateChain() throws ApduConnectionException {
        try {
            setPublicKeyToVerification(DnieCwa14890Constants.REF_C_CV_CA_PUBLIC_KEY);
            try {
                verifyCertificate(DnieCwa14890Constants.C_CV_CA);
                try {
                    setPublicKeyToVerification(DnieCwa14890Constants.CHR_C_CV_CA);
                    try {
                        verifyCertificate(DnieCwa14890Constants.C_CV_IFD);
                    } catch (SecureChannelException e) {
                        throw new SecureChannelException("Error en la verificacion del certificado de Terminal", e);
                    }
                } catch (SecureChannelException e2) {
                    throw new SecureChannelException("Error al establecer la clave publica del certificado de CA intermedia de Terminal para su verificacion en tarjeta", e2);
                }
            } catch (SecureChannelException e22) {
                throw new SecureChannelException("Error en la verificacion del certificado de la CA intermedia de Terminal", e22);
            }
        } catch (SecureChannelException e222) {
            throw new SecureChannelException("Error al seleccionar para verificacion la clave publica de la CA raiz de los certificados verificables por la tarjeta", e222);
        }
    }

    public byte[] getRefIccPrivateKey() {
        return DnieCwa14890Constants.REF_ICC_PRIVATE_KEY;
    }

    public byte[] getChrCCvIfd() {
        return DnieCwa14890Constants.CHR_C_CV_IFD;
    }

    public RSAPrivateKey getIfdPrivateKey() {
        return DnieCwa14890Constants.IFD_PRIVATE_KEY;
    }

    public void setKeysToAuthentication(byte[] refPublicKey, byte[] refPrivateKey) throws ApduConnectionException {
        ResponseApdu res = getConnection().transmit(new MseSetAuthenticationKeyApduCommand((byte) 0, refPublicKey, refPrivateKey));
        if (!res.isOk()) {
            throw new SecureChannelException("Error durante el establecimiento de las claves publica y privada para atenticacion (error: " + HexUtils.hexify(res.getBytes(), true) + ")");
        }
    }

    public byte[] getInternalAuthenticateMessage(byte[] randomIfd, byte[] chrCCvIfd) throws ApduConnectionException {
        ResponseApdu res = getConnection().transmit(new InternalAuthenticateApduCommand((byte) 0, randomIfd, chrCCvIfd));
        if (res.isOk()) {
            return res.getData();
        }
        throw new ApduConnectionException("Respuesta invalida en la obtencion del mensaje de autenticacion interna con el codigo: " + res.getStatusWord());
    }

    public boolean externalAuthentication(byte[] extAuthenticationData) throws ApduConnectionException {
        return getConnection().transmit(new ExternalAuthenticateApduCommand((byte) 0, extAuthenticationData)).isOk();
    }

    public PrivateKeyReference getPrivateKey(String alias) {
        this.needsRealCertificates = true;
        if (AUTH_CERT_ALIAS.equals(alias)) {
            return this.authKeyRef;
        }
        if (SIGN_CERT_ALIAS.equals(alias)) {
            return this.signKeyRef;
        }
        return null;
    }

    public byte[] sign(byte[] data, String algorithm, PrivateKeyReference privateKeyReference) throws CryptoCardException {
        if (privateKeyReference instanceof DniePrivateKeyReference) {
            return signOperation(data, algorithm, privateKeyReference);
        }
        throw new IllegalArgumentException("La referencia a la clave privada tiene que ser de tipo DniePrivateKeyReference");
    }

    private byte[] signOperation(byte[] data, String algorithm, PrivateKeyReference privateKeyReference) throws CryptoCardException {
        if (!isSecurityChannelOpen()) {
            verifyAndLoadCertificates();
        }
        try {
            ResponseApdu res = getConnection().transmit(new MseSetSignatureKeyApduCommand((byte) 0, ((DniePrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath()));
            if (res.isOk()) {
                res = getConnection().transmit(new PsoSignHashApduCommand((byte) 0, DigestInfo.encode(algorithm, data, this.cryptoHelper)));
                if (res.isOk()) {
                    return res.getData();
                }
                throw new DnieCardException("Error durante la operacion de firma", res.getStatusWord());
            }
            throw new DnieCardException("Error en el establecimiento de las variables de entorno para firma", res.getStatusWord());
        } catch (Throwable e) {
            throw new DnieCardException("Error en el calculo del hash para firmar", e);
        } catch (LostChannelException e2) {
            try {
                getConnection().close();
                if (getConnection() instanceof Cwa14890OneConnection) {
                    setConnection(((Cwa14890OneConnection) getConnection()).getSubConnection());
                }
                return signOperation(data, algorithm, privateKeyReference);
            } catch (Throwable ex) {
                throw new DnieCardException("No se pudo recuperar el canal seguro para firmar: " + ex, ex);
            }
        } catch (Throwable e3) {
            throw new DnieCardException("Error en la transmision de comandos a la tarjeta", e3);
        }
    }

    private void verifyAndLoadCertificates() throws CryptoCardException {
        if (!isSecurityChannelOpen()) {
            try {
                verifyPin(this.passwordCallback);
                if (this.passwordCallback != null) {
                    this.passwordCallback.clearPassword();
                    System.gc();
                }
            } catch (LostChannelException e) {
                try {
                    getConnection().close();
                    if (getConnection() instanceof Cwa14890OneConnection) {
                        setConnection(((Cwa14890OneConnection) getConnection()).getSubConnection());
                    }
                    verifyAndLoadCertificates();
                } catch (Exception ex) {
                    throw new CryptoCardException("No se pudo recuperar el canal seguro: " + ex, ex);
                }
            } catch (ApduConnectionException e2) {
                throw new CryptoCardException("Error en la apertura del canal seguro: " + e2, e2);
            }
        }
        try {
            if ((this.authCert instanceof FakeX509Certificate) || (this.signCert instanceof FakeX509Certificate)) {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                this.authCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(deflate(selectFileByLocationAndRead(this.authCertPath))));
                this.signCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(deflate(selectFileByLocationAndRead(this.signCertPath))));
            }
        } catch (CertificateException e3) {
            throw new CryptoCardException("Error al cargar los certificados reales del DNIe, no es posible obtener una factoria de certificados X.509", e3);
        } catch (IOException e4) {
            throw new CryptoCardException("Error al cargar los certificados reales del DNIe, error en la descompresion de los datos", e4);
        } catch (Iso7816FourCardException e5) {
            throw new CryptoCardException("Error al cargar los certificados reales del DNIe, no es posible obtener una factoria de certificados X.509", e5);
        }
    }

    protected void selectMasterFile() throws ApduConnectionException, FileNotFoundException {
        selectFileByName(MASTER_FILE_NAME);
    }

    private static byte[] deflate(byte[] compressedCertificate) throws IOException {
        byte[] bUncompLen = compressedCertificate;
        byte[] bCompLen = compressedCertificate;
        int iUncompLen = ((((bUncompLen[3] & 255) << 24) + ((bUncompLen[2] & 255) << 16)) + ((bUncompLen[1] & 255) << 8)) + (bUncompLen[0] & 255);
        int iCompLen = ((((bCompLen[7] & 255) << 24) + ((bCompLen[6] & 255) << 16)) + ((bCompLen[5] & 255) << 8)) + (bCompLen[4] & 255);
        byte[] uncompr = new byte[iUncompLen];
        byte[] bData = new byte[iCompLen];
        System.arraycopy(compressedCertificate, 8, bData, 0, iCompLen);
        if (iUncompLen == iCompLen) {
            return bData;
        }
        Inflater inflater = new Inflater();
        inflater.setInput(bData);
        inflater.setOutput(uncompr);
        int err = inflater.init();
        if (err != 0) {
            System.out.println("JZlib error: " + err);
            throw new IOException("Error al descomprimir el certificado: " + err);
        }
        while (inflater.total_out < ((long) iUncompLen) && inflater.total_in < ((long) iCompLen)) {
            inflater.avail_out = 1;
            inflater.avail_in = 1;
            err = inflater.inflate(0);
            if (err == 1) {
                break;
            } else if (err != 0) {
                System.out.println("JZlib error: " + err);
                throw new IOException("Error al descomprimir el certificado: " + err);
            }
        }
        err = inflater.end();
        if (err == 0) {
            return (byte[]) uncompr.clone();
        }
        System.out.println("JZlib error: " + err);
        throw new IOException("Error al descomprimir el certificado: " + err);
    }

    private boolean isSecurityChannelOpen() {
        return (getConnection() instanceof Cwa14890OneConnection) && getConnection().isOpen() && !(this.authCert instanceof FakeX509Certificate);
    }

    private void loadDataObjects() {
        Dodf dodf = new Dodf();
        try {
            selectMasterFile();
            dodf.setDerValue(selectFileByLocationAndRead(DODF_LOCATION));
        } catch (Asn1Exception e) {
            Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el DODF de la tarjeta: " + e.getMessage());
        } catch (TlvException e2) {
            Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el DODF de la tarjeta: " + e2.getMessage());
        } catch (Exception e3) {
            throw new IllegalStateException("No se ha podido cargar el DODF de la tarjeta: " + e3.getMessage());
        }
        for (int i = 0; i < dodf.getDataObjectCount(); i++) {
            try {
                if (DATA_LABEL_FIRMA.equals(dodf.getDataObjectName(i))) {
                    this.firmaDataPath = new Location(dodf.getDataObjectPath(i));
                    this.firmaData = deflate(selectFileByLocationAndRead(this.firmaDataPath));
                }
                if (DATA_LABEL_FOTO.equals(dodf.getDataObjectName(i))) {
                    this.fotoDataPath = new Location(dodf.getDataObjectPath(i));
                    this.fotoData = deflate(selectFileByLocationAndRead(this.fotoDataPath));
                }
                if (DATA_LABEL_FILI.equals(dodf.getDataObjectName(i))) {
                    this.filiDataPath = new Location(dodf.getDataObjectPath(i));
                    this.filiData = deflate(selectFileByLocationAndRead(this.filiDataPath));
                }
            } catch (IOException e4) {
                Logger.getLogger("es.gob.jmulticard").warning("Error al cargar los objetos del DNIe, error en la descompresion de los datos" + e4.toString());
            } catch (Iso7816FourCardException e5) {
                Logger.getLogger("es.gob.jmulticard").warning("Error al cargar los objetos del DNIe, no es posible obtener una factoria de datos" + e5.toString());
            }
        }
    }

    public EF_COM getEFCOM() throws CryptoCardException {
        throw new UnsupportedOperationException();
    }

    public DG1_Dnie getDataGroup1() throws CryptoCardException {
        throw new UnsupportedOperationException();
    }

    public DG2 getDataGroup2() throws CryptoCardException {
        throw new UnsupportedOperationException();
    }

    public DG7 getDataGroup7() throws CryptoCardException {
        throw new UnsupportedOperationException();
    }

    public DG11 getDataGroup11() throws CryptoCardException {
        throw new UnsupportedOperationException();
    }

    public DG13 getDataGroup13() throws CryptoCardException {
        throw new UnsupportedOperationException();
    }

    public byte[] getDataObject(String label) throws CryptoCardException {
        try {
            if (!HexUtils.arrayEquals(getSerialNumber(), this.serialID)) {
                loadDataObjects();
            }
            if (DATA_LABEL_FOTO.equals(label)) {
                return this.fotoData;
            }
            if (DATA_LABEL_FIRMA.equals(label)) {
                return this.firmaData;
            }
            if (DATA_LABEL_FILI.equals(label)) {
                return this.filiData;
            }
            return null;
        } catch (ApduConnectionException e) {
            throw new CryptoCardException(e.getMessage());
        }
    }
}

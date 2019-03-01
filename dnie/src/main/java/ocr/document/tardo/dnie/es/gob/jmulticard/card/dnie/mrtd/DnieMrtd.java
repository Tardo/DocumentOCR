package es.gob.jmulticard.card.dnie.mrtd;

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
import es.gob.jmulticard.card.dnie.BurnedDnieCardException;
import es.gob.jmulticard.card.dnie.FakeX509Certificate;
import es.gob.jmulticard.card.iso7816eight.Iso7816EightCard;
import es.gob.jmulticard.card.iso7816four.FileNotFoundException;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.jse.smartcardio.SmartCardMRTDConnection;
import es.gob.jmulticard.ui.passwordcallback.CancelledOperationException;
import es.gob.jmulticard.ui.passwordcallback.gui.DialogBuilder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import javax.security.auth.callback.PasswordCallback;

public final class DnieMrtd extends Iso7816EightCard implements CryptoCard, Cwa14890Card {
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
    private static final byte PASSPORT_DG_01 = (byte) 1;
    private static final byte PASSPORT_DG_02 = (byte) 2;
    private static final byte PASSPORT_DG_07 = (byte) 7;
    private static final byte PASSPORT_DG_11 = (byte) 11;
    private static final byte PASSPORT_DG_13 = (byte) 13;
    private static final byte PASSPORT_EF_COM = (byte) 30;
    private static final Location PRKDF_LOCATION = new Location("50156001");
    private static final byte[] REF_RCA_ICC_PUBLIC_KEY = new byte[]{(byte) 96, (byte) 32};
    private static boolean RequiresVerifyPin = false;
    private static final String SIGN_CERT_ALIAS = "CertFirmaDigital";
    private static final String SIGN_KEY_LABEL = "KprivFirmaDigital";
    private static final boolean TEST_VERSION = false;
    private X509Certificate authCert;
    private Location authCertPath;
    private DnieMrtdPrivateKeyReference authKeyRef;
    private CryptoHelper cryptoHelper = null;
    private DG1_Dnie dg1;
    private DG11 dg11;
    private DG13 dg13;
    private DG2 dg2;
    private DG7 dg7;
    private EF_COM efcom;
    private final boolean fastMode;
    private byte[] filiData;
    private byte[] firmaData;
    private byte[] fotoData;
    private X509Certificate intermediateCaCerICC;
    private X509Certificate intermediateCaCert;
    private boolean m_securePINChannel = false;
    private boolean m_secureUserChannel = false;
    private boolean needsRealCertificates = false;
    private final PasswordCallback passwordCallback;
    private X509Certificate signCert;
    private Location signCertPath;
    private DnieMrtdPrivateKeyReference signKeyRef;

    private void connect(ApduConnection conn) throws BurnedDnieCardException, InvalidCardException, ApduConnectionException {
        if (conn == null) {
            throw new IllegalArgumentException("La conexion no puede ser nula");
        } else if (!(conn instanceof SmartCardMRTDConnection)) {
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

    public DnieMrtd(ApduConnection conn, PasswordCallback pwc, CryptoHelper cryptoHelper) throws ApduConnectionException, InvalidCardException, BurnedDnieCardException {
        super((byte) 0, conn);
        connect(conn);
        this.passwordCallback = pwc;
        if (cryptoHelper == null) {
            throw new IllegalArgumentException("El CryptoHelper no puede ser nula");
        }
        this.cryptoHelper = cryptoHelper;
        this.fastMode = Boolean.getBoolean(FAST_MODE_PROPERTY);
        try {
            preloadCertificates();
            loadKeyReferences();
        } catch (IllegalStateException e) {
        }
    }

    private void loadKeyReferences() {
        PrKdf prKdf = new PrKdf();
        try {
            prKdf.setDerValue(selectFileByLocationAndRead(PRKDF_LOCATION));
            for (int i = 0; i < prKdf.getKeyCount(); i++) {
                if (AUTH_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                    this.authKeyRef = new DnieMrtdPrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), AUTH_KEY_LABEL);
                } else if (SIGN_KEY_LABEL.equals(prKdf.getKeyName(i))) {
                    this.signKeyRef = new DnieMrtdPrivateKeyReference(this, prKdf.getKeyIdentifier(i), new Location(prKdf.getKeyPath(i)), SIGN_KEY_LABEL);
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException("No se ha podido cargar el PrKDF de la tarjeta: " + e.getMessage());
        }
    }

    public byte[] getSerialNumber() throws ApduConnectionException {
        try {
            ResponseApdu response = getConnection().transmit(new GetChipInfoApduCommand());
            if (response.isOk()) {
                return response.getData();
            }
            throw new ApduConnectionException("Respuesta invalida en la obtencion del numero de serie con el codigo: " + response.getStatusWord());
        } catch (InvalidCryptographicChecksum e) {
            try {
                getConnection().close();
                this.needsRealCertificates = !this.fastMode;
                if (getConnection() instanceof Cwa14890OneConnection) {
                    setConnection(((Cwa14890OneConnection) getConnection()).getSubConnection());
                }
                return getSerialNumber();
            } catch (Exception ex) {
                throw new ApduConnectionException("Error reestableciendo el canal de comunicacion", ex);
            }
        } catch (Exception e2) {
            throw new ApduConnectionException("Error al obtener número de serie", e2);
        }
    }

    public String getCardName() {
        return "DNIe";
    }

    public String[] getAliases() {
        return new String[]{AUTH_CERT_ALIAS, SIGN_CERT_ALIAS};
    }

    private void loadDataGroups(int dataGroup) {
        switch (dataGroup) {
            case 1:
                if (this.dg1 == null) {
                    this.dg1 = ((SmartCardMRTDConnection) getConnection()).readDG1();
                    return;
                }
                return;
            case 2:
                if (this.dg2 == null) {
                    this.dg2 = ((SmartCardMRTDConnection) getConnection()).readDG2();
                    return;
                }
                return;
            case 7:
                if (this.dg7 == null) {
                    this.dg7 = ((SmartCardMRTDConnection) getConnection()).readDG7();
                    return;
                }
                return;
            case 11:
                if (this.dg11 == null) {
                    this.dg11 = ((SmartCardMRTDConnection) getConnection()).readDG11();
                    return;
                }
                return;
            case 13:
                if (this.dg13 == null) {
                    this.dg13 = ((SmartCardMRTDConnection) getConnection()).readDG13();
                    return;
                }
                return;
            case 30:
                if (this.efcom == null) {
                    this.efcom = ((SmartCardMRTDConnection) getConnection()).readEFCOM();
                    return;
                }
                return;
            default:
                try {
                    throw new IllegalStateException("No es posible acceder al DG solicitado");
                } catch (IllegalStateException e) {
                    throw e;
                } catch (Exception e2) {
                    throw new IllegalStateException("No se ha podido cargar el DG indicado (DG-" + dataGroup + ")");
                }
        }
    }

    private void preloadCertificates() {
        Cdf cdf = new Cdf();
        try {
            selectMasterFile();
            cdf.setDerValue(selectFileByLocationAndRead(CDF_LOCATION));
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
                        this.intermediateCaCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(deflate(selectCompressedFileByLocationAndRead(new Location(cdf.getCertificatePath(i))))));
                    } catch (Exception e) {
                        Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el certificado de la autoridad intermedia de la DGP: " + e.toString());
                        this.intermediateCaCert = null;
                    }
                }
            }
        } catch (Asn1Exception e2) {
            Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el CDF de la tarjeta: " + e2.getMessage());
            throw new IllegalStateException("No se ha podido cargar el CDF de la tarjeta: " + e2.getMessage());
        } catch (TlvException e3) {
            Logger.getLogger("es.gob.jmulticard").warning("No se ha podido cargar el CDF de la tarjeta: " + e3.getMessage());
            throw new IllegalStateException("No se ha podido cargar el CDF de la tarjeta: " + e3.getMessage());
        } catch (Exception e4) {
            String strError;
            if (e4.getMessage().toLowerCase().contains("tag was lost")) {
                strError = "Se ha perdido la conexión con el DNIe.";
            } else {
                strError = "No se han podido cargar los certificados de la tarjeta: " + e4.getMessage();
            }
            throw new IllegalStateException(strError);
        }
    }

    private void loadCertificates() throws CryptoCardException {
        if (!isSecurityUserChannelOpen()) {
            verifyAndLoadCertificates();
        }
    }

    public X509Certificate getCertificate(String alias) throws CryptoCardException {
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
    }

    public void verifyCaIntermediateIcc() throws CertificateException, IOException {
        try {
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(DnieMrtdCwa14890Constants.CA_COMPONENT_PUBLIC_KEY.getEncoded()));
            this.intermediateCaCerICC = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(selectFileByIdAndRead(REF_RCA_ICC_PUBLIC_KEY)));
            this.intermediateCaCerICC.verify((RSAPublicKey) publicKey);
        } catch (Exception e) {
            throw new SecureChannelException("Error al verificar certificado de la CA intermedia de componentes", e);
        }
    }

    public void verifyIcc() throws CertificateException, IOException {
        try {
            PublicKey iccPublicKey = this.intermediateCaCerICC.getPublicKey();
            ((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(selectFileByIdAndRead(CERT_ICC_FILE_ID)))).verify((RSAPublicKey) iccPublicKey);
        } catch (Exception e) {
            throw new SecureChannelException("Error al verificar certificado ICC de componentes", e);
        }
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
            setPublicKeyToVerification(DnieMrtdCwa14890Constants.REF_C_CV_CA_PUBLIC_KEY);
            try {
                verifyCertificate(DnieMrtdCwa14890Constants.C_CV_CA);
                try {
                    setPublicKeyToVerification(DnieMrtdCwa14890Constants.CHR_C_CV_CA);
                    try {
                        if ((getConnection() instanceof SmartCardMRTDConnection) || RequiresVerifyPin) {
                            verifyCertificate(DnieMrtdCwa14890Constants.C_CV_IFD_PIN);
                        }
                        if ((getConnection() instanceof Cwa14890OneConnection) && !RequiresVerifyPin) {
                            verifyCertificate(DnieMrtdCwa14890Constants.C_CV_IFD_USER);
                        }
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
        return DnieMrtdCwa14890Constants.REF_ICC_PRIVATE_KEY;
    }

    public byte[] getChrCCvIfd() {
        if ((getConnection() instanceof SmartCardMRTDConnection) || RequiresVerifyPin) {
            return DnieMrtdCwa14890Constants.CHR_C_CV_IFD_PIN;
        }
        return DnieMrtdCwa14890Constants.CHR_C_CV_IFD_USER;
    }

    public RSAPrivateKey getIfdPrivateKey() {
        if ((getConnection() instanceof SmartCardMRTDConnection) || RequiresVerifyPin) {
            return DnieMrtdCwa14890Constants.IFD_PRIVATE_KEY_PIN;
        }
        return DnieMrtdCwa14890Constants.IFD_PRIVATE_KEY_USER;
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

    public byte[] sign(byte[] data, String algorithm, PrivateKeyReference privateKeyReference) throws CryptoCardException, CancelledOperationException {
        if (privateKeyReference instanceof DnieMrtdPrivateKeyReference) {
            try {
                if (needsPINVerification()) {
                    establishPINChannel();
                }
                if (Boolean.getBoolean(AUTHENTICATION_CONFIRMATION_PROPERTY) || !AUTH_KEY_LABEL.equals(((DnieMrtdPrivateKeyReference) privateKeyReference).getLabel())) {
                    try {
                        if (DialogBuilder.showSignatureConfirmDialog(AUTH_KEY_LABEL.equals(((DnieMrtdPrivateKeyReference) privateKeyReference).getLabel())) == 1) {
                            throw new CancelledOperationException("Operacion de firma no autorizada por el usuario");
                        }
                    } catch (Exception e) {
                        throw new CancelledOperationException("Operacion de firma no autorizada por el usuario");
                    }
                }
                return signOperation(data, algorithm, privateKeyReference);
            } catch (Exception e2) {
                throw new CryptoCardException(e2.getMessage());
            }
        }
        throw new IllegalArgumentException("La referencia a la clave privada tiene que ser de tipo DnieMrtdPrivateKeyReference");
    }

    private byte[] signOperation(byte[] data, String algorithm, PrivateKeyReference privateKeyReference) throws CryptoCardException {
        if (!isSecurityUserChannelOpen()) {
            establishUserChannel();
        }
        try {
            ResponseApdu res = getConnection().transmit(new MseSetSignatureKeyApduCommand((byte) 0, ((DnieMrtdPrivateKeyReference) privateKeyReference).getKeyPath().getLastFilePath()));
            if (res.isOk()) {
                res = getConnection().transmit(new PsoSignHashApduCommand((byte) 0, DigestInfo.encode(algorithm, data, this.cryptoHelper)));
                if (res.isOk()) {
                    RequiresVerifyPin = true;
                    return res.getData();
                }
                throw new DnieMrtdCardException("Error durante la operacion de firma", res.getStatusWord());
            }
            throw new DnieMrtdCardException("Error en el establecimiento de las variables de entorno para firma", res.getStatusWord());
        } catch (Throwable e) {
            throw new DnieMrtdCardException("Error en el calculo del hash para firmar", e);
        } catch (Throwable e2) {
            throw new DnieMrtdCardException("Error en la transmision de comandos a la tarjeta", e2);
        } catch (Throwable e22) {
            throw new DnieMrtdCardException("Error en la operación de firma", e22);
        }
    }

    private void verifyAndLoadCertificates() throws CryptoCardException {
        if (!((isSecurityChannelOpen() && this.m_secureUserChannel) || ((getConnection() instanceof Cwa14890OneConnection) && this.m_secureUserChannel))) {
            establishPINChannel();
        }
        try {
            if ((this.authCert instanceof FakeX509Certificate) || (this.signCert instanceof FakeX509Certificate)) {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                this.authCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(deflate(selectCompressedFileByLocationAndRead(this.authCertPath))));
                this.signCert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(deflate(selectCompressedFileByLocationAndRead(this.signCertPath))));
            }
        } catch (CertificateException e) {
            throw new CryptoCardException("Error al cargar los certificados reales del DNIe, no es posible obtener una factoria de certificados X.509", e);
        } catch (IOException e2) {
            throw new CryptoCardException("Error al cargar los certificados reales del DNIe, error en la descompresion de los datos", e2);
        } catch (Iso7816FourCardException e3) {
            throw new CryptoCardException("Error al cargar los certificados reales del DNIe, no es posible obtener una factoria de certificados X.509", e3);
        }
    }

    protected void selectMasterFile() throws ApduConnectionException, FileNotFoundException {
        selectFileByName(MASTER_FILE_NAME);
    }

    private static byte[] deflate(byte[] compressedCertificate) throws IOException {
        int iCompLen;
        byte[] bData;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        Inflater decompressor = new Inflater();
        decompressor.setInput(compressedCertificate, 8, compressedCertificate.length - 8);
        byte[] buf = new byte[1024];
        while (!decompressor.finished()) {
            int count = decompressor.inflate(buf);
            if (count == 0) {
                throw new DataFormatException();
            }
            try {
                buffer.write(buf, 0, count);
            } catch (DataFormatException e) {
                byte[] bUncompLen = compressedCertificate;
                byte[] bCompLen = compressedCertificate;
                iUncompLen = ((((bUncompLen[3] & 255) << 24) + ((bUncompLen[2] & 255) << 16)) + ((bUncompLen[1] & 255) << 8)) + (bUncompLen[0] & 255);
                iCompLen = ((((bCompLen[7] & 255) << 24) + ((bCompLen[6] & 255) << 16)) + ((bCompLen[5] & 255) << 8)) + (bCompLen[4] & 255);
                uncompr = new byte[iUncompLen];
                bData = new byte[iCompLen];
                System.arraycopy(compressedCertificate, 8, bData, 0, iCompLen);
                int iUncompLen;
                if (iUncompLen == iCompLen) {
                    return bData;
                }
                byte[] uncompr;
                com.jcraft.jzlib.Inflater inflater = new com.jcraft.jzlib.Inflater();
                inflater.setInput(bData);
                inflater.setOutput(uncompr);
                int err = inflater.init();
                if (err != 0) {
                    System.out.println("JZlib error: " + err);
                    throw new IOException("Error al descomprimir el certificado: " + err);
                }
                do {
                    if (inflater.total_out < ((long) iUncompLen) && inflater.total_in < ((long) iCompLen)) {
                        inflater.avail_out = 1;
                        inflater.avail_in = 1;
                        err = inflater.inflate(0);
                        if (err == 1) {
                        }
                    }
                    err = inflater.end();
                    if (err == 0) {
                        return (byte[]) uncompr.clone();
                    }
                    System.out.println("JZlib error: " + err);
                    throw new IOException("Error al descomprimir el certificado: " + err);
                } while (err == 0);
                System.out.println("JZlib error: " + err);
                throw new IOException("Error al descomprimir el certificado: " + err);
            } catch (Exception ex) {
                throw new IOException("Error al descomprimir el certificado: " + ex);
            }
        }
        return buffer.toByteArray();
    }

    private boolean isSecurityChannelOpen() {
        return (getConnection() instanceof Cwa14890OneConnection) && getConnection().isOpen() && !(this.authCert instanceof FakeX509Certificate);
    }

    private boolean isSecurityUserChannelOpen() {
        return this.m_secureUserChannel;
    }

    private boolean isSecurityPINChannelOpen() {
        return this.m_securePINChannel;
    }

    private boolean needsPINVerification() {
        return RequiresVerifyPin;
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
                    this.firmaData = deflate(selectCompressedFileByLocationAndRead(new Location(dodf.getDataObjectPath(i))));
                }
                if (DATA_LABEL_FOTO.equals(dodf.getDataObjectName(i))) {
                    this.fotoData = deflate(selectCompressedFileByLocationAndRead(new Location(dodf.getDataObjectPath(i))));
                }
                if (DATA_LABEL_FILI.equals(dodf.getDataObjectName(i))) {
                    this.filiData = deflate(selectCompressedFileByLocationAndRead(new Location(dodf.getDataObjectPath(i))));
                }
            } catch (IOException e4) {
                Logger.getLogger("es.gob.jmulticard").warning("Error al cargar los objetos del DNIe, error en la descompresion de los datos" + e4.toString());
            } catch (Iso7816FourCardException e5) {
                Logger.getLogger("es.gob.jmulticard").warning("Error al cargar los objetos del DNIe, no es posible obtener una factoria de datos" + e5.toString());
            }
        }
    }

    public EF_COM getEFCOM() throws CryptoCardException {
        loadDataGroups(30);
        return this.efcom;
    }

    public DG1_Dnie getDataGroup1() throws CryptoCardException {
        loadDataGroups(1);
        return this.dg1;
    }

    public DG2 getDataGroup2() throws CryptoCardException {
        loadDataGroups(2);
        return this.dg2;
    }

    public DG7 getDataGroup7() throws CryptoCardException {
        loadDataGroups(7);
        return this.dg7;
    }

    public DG11 getDataGroup11() throws CryptoCardException {
        loadDataGroups(11);
        return this.dg11;
    }

    public DG13 getDataGroup13() throws CryptoCardException {
        loadDataGroups(13);
        return this.dg13;
    }

    public byte[] getDataObject(String label) throws CryptoCardException {
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
    }

    private void establishPINChannel() throws CryptoCardException {
        if (!this.m_securePINChannel || this.m_secureUserChannel) {
            Cwa14890OneConnection secureConnection = new Cwa14890OneConnection(this, getConnection(), this.cryptoHelper);
            try {
                selectMasterFile();
                setConnection(secureConnection);
                this.m_securePINChannel = true;
                this.m_secureUserChannel = false;
                Security.removeProvider("SC");
            } catch (ApduConnectionException e) {
                throw new CryptoCardException("Error en el establecimiento del canal seguro", e);
            } catch (FileNotFoundException e2) {
                e2.printStackTrace();
            }
        }
        try {
            verifyPin(this.passwordCallback);
            RequiresVerifyPin = false;
            if (this.passwordCallback != null) {
                this.passwordCallback.clearPassword();
                System.gc();
            }
            establishUserChannel();
            RequiresVerifyPin = false;
        } catch (ApduConnectionException e3) {
            throw new CryptoCardException("Error en la apertura del canal seguro: ", e3);
        } catch (CancelledOperationException e4) {
            throw e4;
        } catch (Exception e5) {
            throw new CryptoCardException("Error en la operación de establishPINChannel", e5);
        }
    }

    private void establishUserChannel() throws CryptoCardException {
        if (!isSecurityUserChannelOpen()) {
            Cwa14890OneConnection secureConnection = new Cwa14890OneConnection(this, getConnection(), this.cryptoHelper);
            try {
                selectMasterFile();
                setConnection(secureConnection);
                RequiresVerifyPin = false;
                this.m_secureUserChannel = true;
                this.m_securePINChannel = false;
            } catch (ApduConnectionException e) {
                throw new CryptoCardException("Error en el establecimiento del canal seguro", e);
            } catch (FileNotFoundException e2) {
                e2.printStackTrace();
            }
        }
    }
}

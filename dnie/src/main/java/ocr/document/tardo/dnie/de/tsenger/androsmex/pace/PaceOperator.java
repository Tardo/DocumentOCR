package de.tsenger.androsmex.pace;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.util.Log;
import de.tsenger.androsmex.IsoDepCardHandler;
import de.tsenger.androsmex.asn1.AmDHPublicKey;
import de.tsenger.androsmex.asn1.AmECPublicKey;
import de.tsenger.androsmex.asn1.BSIObjectIdentifiers;
import de.tsenger.androsmex.asn1.DomainParameter;
import de.tsenger.androsmex.asn1.DynamicAuthenticationData;
import de.tsenger.androsmex.asn1.PaceDomainParameterInfo;
import de.tsenger.androsmex.asn1.PaceInfo;
import de.tsenger.androsmex.crypto.AmAESCrypto;
import de.tsenger.androsmex.crypto.AmCryptoProvider;
import de.tsenger.androsmex.crypto.AmDESCrypto;
import de.tsenger.androsmex.iso7816.CommandAPDU;
import de.tsenger.androsmex.iso7816.MSESetAT;
import de.tsenger.androsmex.iso7816.ResponseAPDU;
import de.tsenger.androsmex.iso7816.SecureMessaging;
import de.tsenger.androsmex.iso7816.SecureMessagingException;
import de.tsenger.androsmex.tools.Converter;
import de.tsenger.androsmex.tools.HexString;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.math.ec.ECCurve.Fp;
import org.spongycastle.util.Arrays;

public class PaceOperator extends AsyncTask<Void, String, String> {
    static final String TAG = "NfcConnection";
    private byte[] X1;
    private final IsoDepCardHandler card;
    private Context context;
    private AmCryptoProvider crypto = null;
    private DHParameters dhParameters = null;
    private DomainParameter dp = null;
    private X9ECParameters ecdhParameters = null;
    long endtime = 0;
    private int keyLength = 0;
    private Logger logger;
    private byte[] nonce_s;
    private byte[] nonce_z;
    private Pace pace = null;
    private byte[] passwordBytes;
    private int passwordRef = 0;
    private String protocolOIDString;
    private SecureMessaging sm;
    long starttime = 0;
    private int terminalType = 0;

    public PaceOperator(IsoDepCardHandler card) {
        this.card = card;
        this.context = null;
    }

    public PaceOperator(IsoDepCardHandler card, Context context) {
        this.card = card;
        this.context = context;
    }

    public void setAuthTemplate(PaceInfo pi, String password) {
        this.dp = new DomainParameter(pi.getParameterId().intValue());
        this.logger = null;
        this.passwordRef = 2;
        this.terminalType = 0;
        this.protocolOIDString = pi.getProtocolOID();
        if (this.passwordRef == 1) {
            this.passwordBytes = calcSHA1(password.getBytes());
        } else {
            this.passwordBytes = password.getBytes();
        }
        getStandardizedDomainParameters(pi.getParameterId().intValue());
        if (this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_DH_GM.toString()) || this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_DH_IM.toString())) {
            this.pace = new PaceDH(this.dhParameters);
        } else if (this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_ECDH_GM.toString()) || this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_ECDH_IM.toString())) {
            this.pace = new PaceECDH(this.ecdhParameters);
        }
        getCryptoInformation(pi);
    }

    public void setAuthTemplate(PaceInfo pi, String password, Logger logger, SharedPreferences prefs) {
        this.dp = new DomainParameter(pi.getParameterId().intValue());
        this.logger = logger;
        this.passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
        this.terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));
        this.protocolOIDString = pi.getProtocolOID();
        if (this.passwordRef == 1) {
            this.passwordBytes = calcSHA1(password.getBytes());
        } else {
            this.passwordBytes = password.getBytes();
        }
        getStandardizedDomainParameters(pi.getParameterId().intValue());
        if (this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_DH_GM.toString()) || this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_DH_IM.toString())) {
            this.pace = new PaceDH(this.dhParameters);
        } else if (this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_ECDH_GM.toString()) || this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_ECDH_IM.toString())) {
            this.pace = new PaceECDH(this.ecdhParameters);
        }
        getCryptoInformation(pi);
    }

    public void setAuthTemplate(PaceInfo pi, PaceDomainParameterInfo pdpi, String password, Logger logger, SharedPreferences prefs) throws Exception {
        this.logger = logger;
        this.protocolOIDString = pi.getProtocolOID();
        this.passwordRef = Integer.parseInt(prefs.getString("pref_list_password", "0"));
        this.terminalType = Integer.parseInt(prefs.getString("pref_list_terminal", "0"));
        if (pi.getParameterId().intValue() >= 0 && pi.getParameterId().intValue() <= 31) {
            throw new Exception("ParameterID number 0 to 31 is used for standardized domain parameters!");
        } else if (pi.getParameterId().intValue() != pdpi.getParameterId()) {
            throw new Exception("PaceInfo doesn't match the PaceDomainParameterInfo");
        } else {
            if (this.passwordRef == 1) {
                this.passwordBytes = calcSHA1(password.getBytes());
            } else {
                this.passwordBytes = password.getBytes();
            }
            getProprietaryDomainParameters(pdpi);
            if (this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_DH_GM.toString()) || this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_DH_IM.toString())) {
                this.pace = new PaceDH(this.dhParameters);
            } else if (this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_ECDH_GM.toString()) || this.protocolOIDString.startsWith(BSIObjectIdentifiers.id_PACE_ECDH_IM.toString())) {
                this.pace = new PaceECDH(this.ecdhParameters);
            }
            getCryptoInformation(pi);
        }
    }

    public void performPACE() throws IOException, SecureMessagingException, PaceException, InterruptedException {
        int resp = sendMSESetAT(this.terminalType).getSW();
        if (resp != 36864) {
            Log.d(TAG, "MSE:Set AT failed. SW: " + Integer.toHexString(resp));
        }
        this.nonce_z = getNonce().getDataObject(0);
        this.nonce_s = decryptNonce(this.nonce_z);
        this.X1 = this.pace.getX1(this.nonce_s);
        byte[] X2 = this.pace.getX2(mapNonce(this.X1).getDataObject(2));
        byte[] Y2 = performKeyAgreement(X2).getDataObject(4);
        byte[] S = this.pace.getSharedSecret_K(Y2);
        byte[] kenc = getKenc(S);
        byte[] kmac = getKmac(S);
        if (Arrays.areEqual(performMutualAuthentication(calcAuthToken(kmac, Y2)).getDataObject(6), calcAuthToken(kmac, X2))) {
            this.sm = new SecureMessaging(this.crypto, kenc, kmac, new byte[this.crypto.getBlockSize()]);
            this.card.setSecureMessaging(this.sm);
            return;
        }
        throw new PaceException("Mutual Authentication failed! Tokens are different");
    }

    private byte[] calcAuthToken(byte[] kmac, byte[] data) {
        if (this.pace instanceof PaceECDH) {
            return this.crypto.getMAC(kmac, new AmECPublicKey(this.protocolOIDString, Converter.byteArrayToECPoint(data, (Fp) this.dp.getECParameter().getCurve())).getEncoded());
        } else if (!(this.pace instanceof PaceDH)) {
            return null;
        } else {
            return this.crypto.getMAC(kmac, new AmDHPublicKey(this.protocolOIDString, new BigInteger(data)).getEncoded());
        }
    }

    private DynamicAuthenticationData getNonce() throws SecureMessagingException, PaceException, IOException {
        return sendGeneralAuthenticate(true, new byte[]{(byte) 124, (byte) 0});
    }

    private DynamicAuthenticationData sendGeneralAuthenticate(boolean chaining, byte[] data) throws SecureMessagingException, PaceException, IOException {
        int i;
        if (chaining) {
            i = 16;
        } else {
            i = 0;
        }
        CommandAPDU capdu = new CommandAPDU(i, (int) CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA, 0, 0, data);
        ResponseAPDU resp = this.card.transceive(capdu);
        if (resp.getSW() == 26755) {
            resp = this.card.transceive(capdu);
        }
        if (resp.getSW() == 36864) {
            return new DynamicAuthenticationData(resp.getData());
        }
        throw new PaceException("General Authentication returns: " + HexString.bufferToHex(resp.getBytes()));
    }

    private DynamicAuthenticationData mapNonce(byte[] mappingData) throws SecureMessagingException, PaceException, IOException {
        DynamicAuthenticationData dad81 = new DynamicAuthenticationData();
        dad81.addDataObject(1, mappingData);
        return sendGeneralAuthenticate(true, dad81.getDEREncoded());
    }

    private DynamicAuthenticationData performMutualAuthentication(byte[] authToken) throws SecureMessagingException, PaceException, IOException {
        DynamicAuthenticationData dad85 = new DynamicAuthenticationData();
        dad85.addDataObject(5, authToken);
        return sendGeneralAuthenticate(false, dad85.getDEREncoded());
    }

    private DynamicAuthenticationData performKeyAgreement(byte[] ephemeralPK) throws PaceException, SecureMessagingException, IOException {
        DynamicAuthenticationData dad83 = new DynamicAuthenticationData();
        dad83.addDataObject(3, ephemeralPK);
        return sendGeneralAuthenticate(true, dad83.getDEREncoded());
    }

    private byte[] decryptNonce(byte[] z) {
        return this.crypto.decryptBlock(getKey(this.keyLength, this.passwordBytes, 3), z);
    }

    private byte[] getKenc(byte[] sharedSecret_S) {
        return getKey(this.keyLength, sharedSecret_S, 1);
    }

    private byte[] getKmac(byte[] sharedSecret_S) {
        return getKey(this.keyLength, sharedSecret_S, 2);
    }

    private ResponseAPDU sendMSESetAT(int terminalType) throws IOException, SecureMessagingException {
        MSESetAT mse = new MSESetAT();
        mse.setAT(1);
        mse.setProtocol(this.protocolOIDString);
        mse.setKeyReference(this.passwordRef);
        switch (terminalType) {
            case 0:
                break;
            case 1:
                mse.setISChat();
                break;
            case 2:
                mse.setATChat();
                break;
            case 3:
                mse.setSTChat();
                break;
            default:
                throw new IllegalArgumentException("Unknown Terminal Reference: " + terminalType);
        }
        return this.card.transceive(mse.getCommandAPDU());
    }

    private void getStandardizedDomainParameters(int parameterId) {
        switch (parameterId) {
            case 0:
                this.dhParameters = DHStandardizedDomainParameters.modp1024_160();
                return;
            case 1:
                this.dhParameters = DHStandardizedDomainParameters.modp2048_224();
                return;
            case 3:
                this.dhParameters = DHStandardizedDomainParameters.modp2048_256();
                return;
            case 8:
                this.ecdhParameters = SECNamedCurves.getByName("secp192r1");
                return;
            case 9:
                this.ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp192r1");
                return;
            case 10:
                this.ecdhParameters = SECNamedCurves.getByName("secp224r1");
                return;
            case 11:
                this.ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp224r1");
                return;
            case 12:
                this.ecdhParameters = SECNamedCurves.getByName("secp256r1");
                return;
            case 13:
                this.ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp256r1");
                return;
            case 14:
                this.ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp320r1");
                return;
            case 15:
                this.ecdhParameters = SECNamedCurves.getByName("secp384r1");
                return;
            case 16:
                this.ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp384r1");
                return;
            case 17:
                this.ecdhParameters = TeleTrusTNamedCurves.getByName("brainpoolp512r1");
                return;
            case 18:
                this.ecdhParameters = SECNamedCurves.getByName("secp521r1");
                return;
            default:
                return;
        }
    }

    private byte[] getKey(int keyLength, byte[] K, int c) {
        KeyDerivationFunction kdf = new KeyDerivationFunction(K, c);
        switch (keyLength) {
            case 112:
                return kdf.getDESedeKey();
            case 128:
                return kdf.getAES128Key();
            case 192:
                return kdf.getAES192Key();
            case 256:
                return kdf.getAES256Key();
            default:
                return null;
        }
    }

    private void getProprietaryDomainParameters(PaceDomainParameterInfo pdpi) throws PaceException {
        if (pdpi.getDomainParameter().getAlgorithm().toString().contains(BSIObjectIdentifiers.id_ecc.toString())) {
            this.ecdhParameters = new X9ECParameters((ASN1Sequence) pdpi.getDomainParameter().getParameters().getDERObject().toASN1Object());
            return;
        }
        throw new PaceException("Can't decode properietary domain parameters in PaceDomainParameterInfo!");
    }

    private void getCryptoInformation(PaceInfo pi) {
        String protocolOIDString = pi.getProtocolOID();
        if (protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_GM_3DES_CBC_CBC.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_IM_3DES_CBC_CBC.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_GM_3DES_CBC_CBC.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_IM_3DES_CBC_CBC.toString())) {
            this.keyLength = 112;
            this.crypto = new AmDESCrypto();
        } else if (protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_128.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_128.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_128.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_128.toString())) {
            this.keyLength = 128;
            this.crypto = new AmAESCrypto();
        } else if (protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_192.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_192.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_192.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_192.toString())) {
            this.keyLength = 192;
            this.crypto = new AmAESCrypto();
        } else if (protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_256.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_DH_IM_AES_CBC_CMAC_256.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_256.toString()) || protocolOIDString.equals(BSIObjectIdentifiers.id_PACE_ECDH_IM_AES_CBC_CMAC_256.toString())) {
            this.keyLength = 256;
            this.crypto = new AmAESCrypto();
        }
    }

    private byte[] calcSHA1(byte[] input) {
        byte[] md = new byte[20];
        SHA1Digest sha1 = new SHA1Digest();
        sha1.update(input, 0, input.length);
        sha1.doFinal(md, 0);
        return md;
    }

    public SecureMessaging getSMObject() {
        return this.sm;
    }

    protected String doInBackground(Void... params) {
        String str;
        try {
            this.starttime = System.currentTimeMillis();
            performPACE();
            return "PACE established!";
        } catch (IOException e) {
            Log.e(TAG, e.getMessage());
            str = "PACE failed!";
            return str;
        } catch (SecureMessagingException e2) {
            Log.e(TAG, e2.getMessage());
            str = "PACE failed!";
            return str;
        } catch (PaceException e3) {
            Log.e(TAG, e3.getMessage());
            str = "PACE failed!";
            return str;
        } catch (InterruptedException e4) {
            Log.e(TAG, e4.getMessage());
            str = "PACE failed!";
            return str;
        } finally {
            this.endtime = System.currentTimeMillis();
        }
    }

    protected void onProgressUpdate(String... strings) {
        if (strings != null) {
            this.logger.log(Level.INFO, strings[0]);
        }
    }

    protected void onPostExecute(String result) {
        new Intent("pace_finished").putExtra("message", result + "\nTime used: " + (this.endtime - this.starttime) + " ms");
    }
}

package es.gob.jmulticard.card;

import de.tsenger.androsmex.mrtd.DG11;
import de.tsenger.androsmex.mrtd.DG13;
import de.tsenger.androsmex.mrtd.DG1_Dnie;
import de.tsenger.androsmex.mrtd.DG2;
import de.tsenger.androsmex.mrtd.DG7;
import de.tsenger.androsmex.mrtd.EF_COM;
import java.security.cert.X509Certificate;

public interface CryptoCard {
    String[] getAliases() throws CryptoCardException;

    X509Certificate getCertificate(String str) throws CryptoCardException;

    DG1_Dnie getDataGroup1() throws CryptoCardException;

    DG11 getDataGroup11() throws CryptoCardException;

    DG13 getDataGroup13() throws CryptoCardException;

    DG2 getDataGroup2() throws CryptoCardException;

    DG7 getDataGroup7() throws CryptoCardException;

    byte[] getDataObject(String str) throws CryptoCardException;

    EF_COM getEFCOM() throws CryptoCardException;

    PrivateKeyReference getPrivateKey(String str) throws CryptoCardException;

    byte[] sign(byte[] bArr, String str, PrivateKeyReference privateKeyReference) throws CryptoCardException;
}

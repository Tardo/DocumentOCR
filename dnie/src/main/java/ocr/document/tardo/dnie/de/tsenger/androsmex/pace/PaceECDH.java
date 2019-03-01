package de.tsenger.androsmex.pace;

import de.tsenger.androsmex.tools.Converter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.ECPoint.Fp;

public class PaceECDH extends Pace {
    private ECPoint PCD_PK_X1 = null;
    private ECPoint PCD_PK_X2 = null;
    private BigInteger PCD_SK_x1 = null;
    private BigInteger PCD_SK_x2 = null;
    private ECPoint PICC_PK_Y1 = null;
    private ECPoint PICC_PK_Y2 = null;
    private Fp SharedSecret_P = null;
    private ECCurve.Fp curve = null;
    private ECPoint pointG = null;
    private ECPoint pointG_strich = null;
    private final SecureRandom randomGenerator = new SecureRandom();

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public PaceECDH(X9ECParameters cp) {
        this.pointG = cp.getG();
        this.curve = (ECCurve.Fp) cp.getCurve();
        this.randomGenerator.setSeed(new Random().nextLong());
    }

    public byte[] getX1(byte[] s) {
        this.nonce_s = s;
        byte[] x1 = new byte[(this.curve.getFieldSize() / 8)];
        this.randomGenerator.nextBytes(x1);
        this.PCD_SK_x1 = new BigInteger(1, x1);
        this.PCD_PK_X1 = this.pointG.multiply(this.PCD_SK_x1);
        return this.PCD_PK_X1.getEncoded();
    }

    private ECPoint getX2(Fp Y1) {
        this.PICC_PK_Y1 = Y1;
        calculateSharedSecretP();
        calculateNewPointG();
        byte[] x2 = new byte[(this.curve.getFieldSize() / 8)];
        this.randomGenerator.nextBytes(x2);
        this.PCD_SK_x2 = new BigInteger(1, x2);
        this.PCD_PK_X2 = this.pointG_strich.multiply(this.PCD_SK_x2);
        return this.PCD_PK_X2;
    }

    public byte[] getX2(byte[] Y1Bytes) {
        Fp Y1 = null;
        try {
            Y1 = (Fp) Converter.byteArrayToECPoint(Y1Bytes, this.curve);
        } catch (Exception e) {
            System.err.println(e.toString());
            e.printStackTrace();
        }
        return getX2(Y1).getEncoded();
    }

    private void calculateSharedSecretP() {
        this.SharedSecret_P = (Fp) this.PICC_PK_Y1.multiply(this.PCD_SK_x1);
        this.sharedSecret_P = this.SharedSecret_P.getEncoded();
    }

    private void calculateNewPointG() {
        this.pointG_strich = this.pointG.multiply(new BigInteger(1, this.nonce_s)).add(this.SharedSecret_P);
    }

    public byte[] getSharedSecret_K(byte[] Y2) {
        try {
            this.PICC_PK_Y2 = Converter.byteArrayToECPoint(Y2, this.curve);
        } catch (Exception e) {
            System.err.println(e.toString());
            e.printStackTrace();
        }
        this.sharedSecret_K = Converter.bigIntToByteArray(((Fp) this.PICC_PK_Y2.multiply(this.PCD_SK_x2)).getX().toBigInteger());
        return this.sharedSecret_K;
    }
}

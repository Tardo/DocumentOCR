package de.tsenger.androsmex.pace;

import de.tsenger.androsmex.tools.Converter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import org.spongycastle.crypto.params.DHParameters;

public class PaceDH extends Pace {
    private BigInteger PCD_PK_X1 = null;
    private BigInteger PCD_PK_X2 = null;
    private BigInteger PCD_SK_x1 = null;
    private BigInteger PCD_SK_x2 = null;
    private BigInteger PICC_PK_Y1 = null;
    private BigInteger PICC_PK_Y2 = null;
    private BigInteger SharedSecret_K = null;
    private BigInteger SharedSecret_P = null;
    /* renamed from: g */
    private BigInteger f213g = null;
    private BigInteger g_strich = null;
    /* renamed from: p */
    private BigInteger f214p = null;
    private final SecureRandom randomGenerator = new SecureRandom();

    public PaceDH(DHParameters dhParameters) {
        this.f213g = dhParameters.getG();
        this.f214p = dhParameters.getP();
        this.randomGenerator.setSeed(new Random().nextLong());
    }

    public byte[] getX1(byte[] s) {
        this.nonce_s = (byte[]) s.clone();
        byte[] x1 = new byte[(this.f213g.bitLength() / 8)];
        this.randomGenerator.nextBytes(x1);
        this.PCD_SK_x1 = new BigInteger(1, x1);
        this.PCD_PK_X1 = this.f213g.modPow(this.PCD_SK_x1, this.f214p);
        return Converter.bigIntToByteArray(this.PCD_PK_X1);
    }

    public byte[] getX2(byte[] Y1) {
        this.PICC_PK_Y1 = new BigInteger(1, Y1);
        this.SharedSecret_P = this.PICC_PK_Y1.modPow(this.PCD_SK_x1, this.f214p);
        this.sharedSecret_P = this.SharedSecret_P.abs().toByteArray();
        this.g_strich = this.f213g.modPow(new BigInteger(1, this.nonce_s), this.f214p).multiply(this.SharedSecret_P).mod(this.f214p);
        byte[] x2 = new byte[(this.f213g.bitLength() / 8)];
        this.randomGenerator.nextBytes(x2);
        this.PCD_SK_x2 = new BigInteger(1, x2);
        this.PCD_PK_X2 = this.g_strich.modPow(this.PCD_SK_x2, this.f214p);
        return Converter.bigIntToByteArray(this.PCD_PK_X2);
    }

    public byte[] getSharedSecret_K(byte[] Y2) {
        this.PICC_PK_Y2 = new BigInteger(1, Y2);
        this.SharedSecret_K = this.PICC_PK_Y2.modPow(this.PCD_SK_x2, this.f214p);
        this.sharedSecret_K = Converter.bigIntToByteArray(this.SharedSecret_K);
        return this.sharedSecret_K;
    }
}

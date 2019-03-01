package org.spongycastle.jce.provider;

import java.security.MessageDigest;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.GOST3411Digest;
import org.spongycastle.crypto.digests.MD2Digest;
import org.spongycastle.crypto.digests.MD4Digest;
import org.spongycastle.crypto.digests.MD5Digest;
import org.spongycastle.crypto.digests.RIPEMD128Digest;
import org.spongycastle.crypto.digests.RIPEMD160Digest;
import org.spongycastle.crypto.digests.RIPEMD256Digest;
import org.spongycastle.crypto.digests.RIPEMD320Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.digests.SHA384Digest;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.digests.TigerDigest;
import org.spongycastle.crypto.digests.WhirlpoolDigest;

public class JDKMessageDigest extends MessageDigest {
    Digest digest;

    public static class GOST3411 extends JDKMessageDigest implements Cloneable {
        public GOST3411() {
            super(new GOST3411Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            GOST3411 d = (GOST3411) super.clone();
            d.digest = new GOST3411Digest((GOST3411Digest) this.digest);
            return d;
        }
    }

    public static class MD2 extends JDKMessageDigest implements Cloneable {
        public MD2() {
            super(new MD2Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            MD2 d = (MD2) super.clone();
            d.digest = new MD2Digest((MD2Digest) this.digest);
            return d;
        }
    }

    public static class MD4 extends JDKMessageDigest implements Cloneable {
        public MD4() {
            super(new MD4Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            MD4 d = (MD4) super.clone();
            d.digest = new MD4Digest((MD4Digest) this.digest);
            return d;
        }
    }

    public static class MD5 extends JDKMessageDigest implements Cloneable {
        public MD5() {
            super(new MD5Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            MD5 d = (MD5) super.clone();
            d.digest = new MD5Digest((MD5Digest) this.digest);
            return d;
        }
    }

    public static class RIPEMD128 extends JDKMessageDigest implements Cloneable {
        public RIPEMD128() {
            super(new RIPEMD128Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            RIPEMD128 d = (RIPEMD128) super.clone();
            d.digest = new RIPEMD128Digest((RIPEMD128Digest) this.digest);
            return d;
        }
    }

    public static class RIPEMD160 extends JDKMessageDigest implements Cloneable {
        public RIPEMD160() {
            super(new RIPEMD160Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            RIPEMD160 d = (RIPEMD160) super.clone();
            d.digest = new RIPEMD160Digest((RIPEMD160Digest) this.digest);
            return d;
        }
    }

    public static class RIPEMD256 extends JDKMessageDigest implements Cloneable {
        public RIPEMD256() {
            super(new RIPEMD256Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            RIPEMD256 d = (RIPEMD256) super.clone();
            d.digest = new RIPEMD256Digest((RIPEMD256Digest) this.digest);
            return d;
        }
    }

    public static class RIPEMD320 extends JDKMessageDigest implements Cloneable {
        public RIPEMD320() {
            super(new RIPEMD320Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            RIPEMD320 d = (RIPEMD320) super.clone();
            d.digest = new RIPEMD320Digest((RIPEMD320Digest) this.digest);
            return d;
        }
    }

    public static class SHA1 extends JDKMessageDigest implements Cloneable {
        public SHA1() {
            super(new SHA1Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            SHA1 d = (SHA1) super.clone();
            d.digest = new SHA1Digest((SHA1Digest) this.digest);
            return d;
        }
    }

    public static class SHA224 extends JDKMessageDigest implements Cloneable {
        public SHA224() {
            super(new SHA224Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            SHA224 d = (SHA224) super.clone();
            d.digest = new SHA224Digest((SHA224Digest) this.digest);
            return d;
        }
    }

    public static class SHA256 extends JDKMessageDigest implements Cloneable {
        public SHA256() {
            super(new SHA256Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            SHA256 d = (SHA256) super.clone();
            d.digest = new SHA256Digest((SHA256Digest) this.digest);
            return d;
        }
    }

    public static class SHA384 extends JDKMessageDigest implements Cloneable {
        public SHA384() {
            super(new SHA384Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            SHA384 d = (SHA384) super.clone();
            d.digest = new SHA384Digest((SHA384Digest) this.digest);
            return d;
        }
    }

    public static class SHA512 extends JDKMessageDigest implements Cloneable {
        public SHA512() {
            super(new SHA512Digest());
        }

        public Object clone() throws CloneNotSupportedException {
            SHA512 d = (SHA512) super.clone();
            d.digest = new SHA512Digest((SHA512Digest) this.digest);
            return d;
        }
    }

    public static class Tiger extends JDKMessageDigest implements Cloneable {
        public Tiger() {
            super(new TigerDigest());
        }

        public Object clone() throws CloneNotSupportedException {
            Tiger d = (Tiger) super.clone();
            d.digest = new TigerDigest((TigerDigest) this.digest);
            return d;
        }
    }

    public static class Whirlpool extends JDKMessageDigest implements Cloneable {
        public Whirlpool() {
            super(new WhirlpoolDigest());
        }

        public Object clone() throws CloneNotSupportedException {
            Whirlpool d = (Whirlpool) super.clone();
            d.digest = new WhirlpoolDigest((WhirlpoolDigest) this.digest);
            return d;
        }
    }

    protected JDKMessageDigest(Digest digest) {
        super(digest.getAlgorithmName());
        this.digest = digest;
    }

    public void engineReset() {
        this.digest.reset();
    }

    public void engineUpdate(byte input) {
        this.digest.update(input);
    }

    public void engineUpdate(byte[] input, int offset, int len) {
        this.digest.update(input, offset, len);
    }

    public byte[] engineDigest() {
        byte[] digestBytes = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(digestBytes, 0);
        return digestBytes;
    }
}

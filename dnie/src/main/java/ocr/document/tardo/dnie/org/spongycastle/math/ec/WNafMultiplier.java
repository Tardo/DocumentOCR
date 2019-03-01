package org.spongycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.asn1.eac.EACTags;

class WNafMultiplier implements ECMultiplier {
    WNafMultiplier() {
    }

    public byte[] windowNaf(byte width, BigInteger k) {
        byte[] wnaf = new byte[(k.bitLength() + 1)];
        short pow2wB = (short) (1 << width);
        BigInteger pow2wBI = BigInteger.valueOf((long) pow2wB);
        int i = 0;
        int length = 0;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                BigInteger remainder = k.mod(pow2wBI);
                if (remainder.testBit(width - 1)) {
                    wnaf[i] = (byte) (remainder.intValue() - pow2wB);
                } else {
                    wnaf[i] = (byte) remainder.intValue();
                }
                k = k.subtract(BigInteger.valueOf((long) wnaf[i]));
                length = i;
            } else {
                wnaf[i] = (byte) 0;
            }
            k = k.shiftRight(1);
            i++;
        }
        length++;
        byte[] wnafShort = new byte[length];
        System.arraycopy(wnaf, 0, wnafShort, 0, length);
        return wnafShort;
    }

    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo) {
        WNafPreCompInfo wnafPreCompInfo;
        byte width;
        int reqPreCompLen;
        int i;
        if (preCompInfo == null || !(preCompInfo instanceof WNafPreCompInfo)) {
            wnafPreCompInfo = new WNafPreCompInfo();
        } else {
            wnafPreCompInfo = (WNafPreCompInfo) preCompInfo;
        }
        int m = k.bitLength();
        if (m < 13) {
            width = (byte) 2;
            reqPreCompLen = 1;
        } else if (m < 41) {
            width = (byte) 3;
            reqPreCompLen = 2;
        } else if (m < EACTags.COEXISTANT_TAG_ALLOCATION_AUTHORITY) {
            width = (byte) 4;
            reqPreCompLen = 4;
        } else if (m < 337) {
            width = (byte) 5;
            reqPreCompLen = 8;
        } else if (m < 897) {
            width = (byte) 6;
            reqPreCompLen = 16;
        } else if (m < 2305) {
            width = (byte) 7;
            reqPreCompLen = 32;
        } else {
            width = (byte) 8;
            reqPreCompLen = CertificateBody.profileType;
        }
        int preCompLen = 1;
        ECPoint[] preComp = wnafPreCompInfo.getPreComp();
        ECPoint twiceP = wnafPreCompInfo.getTwiceP();
        if (preComp == null) {
            preComp = new ECPoint[]{p};
        } else {
            preCompLen = preComp.length;
        }
        if (twiceP == null) {
            twiceP = p.twice();
        }
        if (preCompLen < reqPreCompLen) {
            ECPoint[] oldPreComp = preComp;
            preComp = new ECPoint[reqPreCompLen];
            System.arraycopy(oldPreComp, 0, preComp, 0, preCompLen);
            for (i = preCompLen; i < reqPreCompLen; i++) {
                preComp[i] = twiceP.add(preComp[i - 1]);
            }
        }
        byte[] wnaf = windowNaf(width, k);
        int l = wnaf.length;
        ECPoint q = p.getCurve().getInfinity();
        for (i = l - 1; i >= 0; i--) {
            q = q.twice();
            if (wnaf[i] != (byte) 0) {
                if (wnaf[i] > (byte) 0) {
                    q = q.add(preComp[(wnaf[i] - 1) / 2]);
                } else {
                    q = q.subtract(preComp[((-wnaf[i]) - 1) / 2]);
                }
            }
        }
        wnafPreCompInfo.setPreComp(preComp);
        wnafPreCompInfo.setTwiceP(twiceP);
        p.setPreCompInfo(wnafPreCompInfo);
        return q;
    }
}

package org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.asn1.eac.EACTags;

class WNafMultiplier implements ECMultiplier {
    WNafMultiplier() {
    }

    public ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger, PreCompInfo preCompInfo) {
        ECPoint[] eCPointArr;
        byte b = (byte) 4;
        int i = 2;
        preCompInfo = (preCompInfo == null || !(preCompInfo instanceof WNafPreCompInfo)) ? new WNafPreCompInfo() : (WNafPreCompInfo) preCompInfo;
        int bitLength = bigInteger.bitLength();
        if (bitLength < 13) {
            b = (byte) 2;
            i = 1;
        } else if (bitLength < 41) {
            b = (byte) 3;
        } else if (bitLength < EACTags.COEXISTANT_TAG_ALLOCATION_AUTHORITY) {
            i = 4;
        } else if (bitLength < 337) {
            b = (byte) 5;
            i = 8;
        } else if (bitLength < 897) {
            b = (byte) 6;
            i = 16;
        } else if (bitLength < 2305) {
            b = (byte) 7;
            i = 32;
        } else {
            i = CertificateBody.profileType;
            b = (byte) 8;
        }
        Object preComp = preCompInfo.getPreComp();
        ECPoint twiceP = preCompInfo.getTwiceP();
        if (preComp == null) {
            preComp = new ECPoint[]{eCPoint};
            bitLength = 1;
        } else {
            bitLength = preComp.length;
        }
        if (twiceP == null) {
            twiceP = eCPoint.twice();
        }
        if (bitLength < i) {
            Object obj = new ECPoint[i];
            System.arraycopy(preComp, 0, obj, 0, bitLength);
            for (int i2 = bitLength; i2 < i; i2++) {
                obj[i2] = twiceP.add(obj[i2 - 1]);
            }
            eCPointArr = obj;
        } else {
            Object obj2 = preComp;
        }
        byte[] windowNaf = windowNaf(b, bigInteger);
        int length = windowNaf.length - 1;
        ECPoint infinity = eCPoint.getCurve().getInfinity();
        for (int i3 = length; i3 >= 0; i3--) {
            infinity = infinity.twice();
            if (windowNaf[i3] != (byte) 0) {
                infinity = windowNaf[i3] > (byte) 0 ? infinity.add(eCPointArr[(windowNaf[i3] - 1) / 2]) : infinity.subtract(eCPointArr[((-windowNaf[i3]) - 1) / 2]);
            }
        }
        preCompInfo.setPreComp(eCPointArr);
        preCompInfo.setTwiceP(twiceP);
        eCPoint.setPreCompInfo(preCompInfo);
        return infinity;
    }

    public byte[] windowNaf(byte b, BigInteger bigInteger) {
        Object obj = new byte[(bigInteger.bitLength() + 1)];
        short s = (short) (1 << b);
        BigInteger valueOf = BigInteger.valueOf((long) s);
        int i = 0;
        int i2 = 0;
        while (bigInteger.signum() > 0) {
            if (bigInteger.testBit(0)) {
                BigInteger mod = bigInteger.mod(valueOf);
                if (mod.testBit(b - 1)) {
                    obj[i2] = (byte) (mod.intValue() - s);
                } else {
                    obj[i2] = (byte) mod.intValue();
                }
                bigInteger = bigInteger.subtract(BigInteger.valueOf((long) obj[i2]));
                i = i2;
            } else {
                obj[i2] = null;
            }
            bigInteger = bigInteger.shiftRight(1);
            i2++;
        }
        i++;
        Object obj2 = new byte[i];
        System.arraycopy(obj, 0, obj2, 0, i);
        return obj2;
    }
}

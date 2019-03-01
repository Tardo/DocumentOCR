package de.tsenger.androsmex.iso7816;

import de.tsenger.androsmex.crypto.AmCryptoProvider;
import java.io.ByteArrayOutputStream;

public class SecureMessaging {
    private AmCryptoProvider crypto = null;
    private byte[] ks_enc = null;
    private byte[] ks_mac = null;
    private byte[] ssc = null;

    public SecureMessaging(AmCryptoProvider acp, byte[] ksenc, byte[] ksmac, byte[] initialSSC) {
        this.crypto = acp;
        this.ks_enc = (byte[]) ksenc.clone();
        this.ks_mac = (byte[]) ksmac.clone();
        this.ssc = (byte[]) initialSSC.clone();
    }

    public CommandAPDU wrap(CommandAPDU capdu) throws SecureMessagingException {
        byte lc = (byte) 0;
        DO97 do97 = null;
        DO87 do87 = null;
        incrementAtIndex(this.ssc, this.ssc.length - 1);
        byte[] header = new byte[4];
        System.arraycopy(capdu.getBytes(), 0, header, 0, 4);
        header[0] = (byte) (header[0] | 12);
        if (getAPDUStructure(capdu) == (byte) 3 || getAPDUStructure(capdu) == (byte) 4) {
            do87 = buildDO87((byte[]) capdu.getData().clone());
            lc = (byte) (do87.getEncoded().length + 0);
        }
        if (getAPDUStructure(capdu) == (byte) 2 || getAPDUStructure(capdu) == (byte) 4) {
            do97 = buildDO97(capdu.getNe());
            lc = (byte) (do97.getEncoded().length + lc);
        }
        DO8E do8E = buildDO8E(header, do87, do97);
        lc = (byte) (do8E.getEncoded().length + lc);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        try {
            bOut.write(header);
            bOut.write(lc);
            if (do87 != null) {
                bOut.write(do87.getEncoded());
            }
            if (do97 != null) {
                bOut.write(do97.getEncoded());
            }
            bOut.write(do8E.getEncoded());
            bOut.write(0);
            return new CommandAPDU(bOut.toByteArray());
        } catch (Throwable e) {
            throw new SecureMessagingException(e);
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public de.tsenger.androsmex.iso7816.ResponseAPDU unwrap(de.tsenger.androsmex.iso7816.ResponseAPDU r29) throws de.tsenger.androsmex.iso7816.SecureMessagingException {
        /*
        r28 = this;
        r10 = 0;
        r16 = 0;
        r13 = 0;
        r0 = r28;
        r0 = r0.ssc;
        r25 = r0;
        r0 = r28;
        r0 = r0.ssc;
        r26 = r0;
        r0 = r26;
        r0 = r0.length;
        r26 = r0;
        r26 = r26 + -1;
        r0 = r28;
        r1 = r25;
        r2 = r26;
        r0.incrementAtIndex(r1, r2);
        r21 = 0;
        r22 = r29.getData();
        r0 = r22;
        r0 = r0.length;
        r25 = r0;
        r0 = r25;
        r0 = new byte[r0];
        r23 = r0;
    L_0x0031:
        r0 = r22;
        r0 = r0.length;
        r25 = r0;
        r0 = r21;
        r1 = r25;
        if (r0 >= r1) goto L_0x00d4;
    L_0x003c:
        r25 = 0;
        r0 = r22;
        r0 = r0.length;
        r26 = r0;
        r26 = r26 - r21;
        r0 = r22;
        r1 = r21;
        r2 = r23;
        r3 = r25;
        r4 = r26;
        java.lang.System.arraycopy(r0, r1, r2, r3, r4);
        r6 = new org.spongycastle.asn1.ASN1InputStream;
        r0 = r23;
        r6.<init>(r0);
        r20 = 0;
        r25 = r6.readObject();	 Catch:{ IOException -> 0x007f }
        r20 = r25.getEncoded();	 Catch:{ IOException -> 0x007f }
        r6.close();	 Catch:{ IOException -> 0x007f }
        r5 = new org.spongycastle.asn1.ASN1InputStream;
        r0 = r20;
        r5.<init>(r0);
        r25 = 0;
        r25 = r20[r25];	 Catch:{ IOException -> 0x00c9 }
        switch(r25) {
            case -121: goto L_0x008a;
            case -114: goto L_0x00b5;
            case -103: goto L_0x009e;
            default: goto L_0x0074;
        };	 Catch:{ IOException -> 0x00c9 }
    L_0x0074:
        r5.close();	 Catch:{ IOException -> 0x00c9 }
        r0 = r20;
        r0 = r0.length;
        r25 = r0;
        r21 = r21 + r25;
        goto L_0x0031;
    L_0x007f:
        r19 = move-exception;
        r25 = new de.tsenger.androsmex.iso7816.SecureMessagingException;
        r0 = r25;
        r1 = r19;
        r0.<init>(r1);
        throw r25;
    L_0x008a:
        r11 = new de.tsenger.androsmex.iso7816.DO87;	 Catch:{ IOException -> 0x00c9 }
        r11.<init>();	 Catch:{ IOException -> 0x00c9 }
        r25 = r5.readObject();	 Catch:{ IOException -> 0x01dc }
        r25 = r25.getEncoded();	 Catch:{ IOException -> 0x01dc }
        r0 = r25;
        r11.fromByteArray(r0);	 Catch:{ IOException -> 0x01dc }
        r10 = r11;
        goto L_0x0074;
    L_0x009e:
        r17 = new de.tsenger.androsmex.iso7816.DO99;	 Catch:{ IOException -> 0x00c9 }
        r17.<init>();	 Catch:{ IOException -> 0x00c9 }
        r25 = r5.readObject();	 Catch:{ IOException -> 0x01e0 }
        r25 = r25.getEncoded();	 Catch:{ IOException -> 0x01e0 }
        r0 = r17;
        r1 = r25;
        r0.fromByteArray(r1);	 Catch:{ IOException -> 0x01e0 }
        r16 = r17;
        goto L_0x0074;
    L_0x00b5:
        r14 = new de.tsenger.androsmex.iso7816.DO8E;	 Catch:{ IOException -> 0x00c9 }
        r14.<init>();	 Catch:{ IOException -> 0x00c9 }
        r25 = r5.readObject();	 Catch:{ IOException -> 0x01e5 }
        r25 = r25.getEncoded();	 Catch:{ IOException -> 0x01e5 }
        r0 = r25;
        r14.fromByteArray(r0);	 Catch:{ IOException -> 0x01e5 }
        r13 = r14;
        goto L_0x0074;
    L_0x00c9:
        r19 = move-exception;
    L_0x00ca:
        r25 = new de.tsenger.androsmex.iso7816.SecureMessagingException;
        r0 = r25;
        r1 = r19;
        r0.<init>(r1);
        throw r25;
    L_0x00d4:
        if (r16 != 0) goto L_0x00de;
    L_0x00d6:
        r25 = new de.tsenger.androsmex.iso7816.SecureMessagingException;
        r26 = "Secure Messaging error: mandatory DO99 not found";
        r25.<init>(r26);
        throw r25;
    L_0x00de:
        r7 = new java.io.ByteArrayOutputStream;
        r7.<init>();
        if (r10 == 0) goto L_0x00ee;
    L_0x00e5:
        r25 = r10.getEncoded();	 Catch:{ IOException -> 0x014f }
        r0 = r25;
        r7.write(r0);	 Catch:{ IOException -> 0x014f }
    L_0x00ee:
        r25 = r16.getEncoded();	 Catch:{ IOException -> 0x014f }
        r0 = r25;
        r7.write(r0);	 Catch:{ IOException -> 0x014f }
        r0 = r28;
        r0 = r0.crypto;
        r25 = r0;
        r0 = r28;
        r0 = r0.ks_mac;
        r26 = r0;
        r0 = r28;
        r0 = r0.ssc;
        r27 = r0;
        r25.init(r26, r27);
        r0 = r28;
        r0 = r0.crypto;
        r25 = r0;
        r26 = r7.toByteArray();
        r8 = r25.getMAC(r26);
        r15 = r13.getData();
        r25 = java.util.Arrays.equals(r8, r15);
        if (r25 != 0) goto L_0x015a;
    L_0x0124:
        r25 = new de.tsenger.androsmex.iso7816.SecureMessagingException;
        r26 = new java.lang.StringBuilder;
        r26.<init>();
        r27 = "Checksum is incorrect!\n Calculated CC: ";
        r26 = r26.append(r27);
        r27 = de.tsenger.androsmex.tools.HexString.bufferToHex(r8);
        r26 = r26.append(r27);
        r27 = "\nCC in DO8E: ";
        r26 = r26.append(r27);
        r27 = de.tsenger.androsmex.tools.HexString.bufferToHex(r15);
        r26 = r26.append(r27);
        r26 = r26.toString();
        r25.<init>(r26);
        throw r25;
    L_0x014f:
        r19 = move-exception;
        r25 = new de.tsenger.androsmex.iso7816.SecureMessagingException;
        r0 = r25;
        r1 = r19;
        r0.<init>(r1);
        throw r25;
    L_0x015a:
        r9 = 0;
        r24 = 0;
        if (r10 == 0) goto L_0x01d1;
    L_0x015f:
        r0 = r28;
        r0 = r0.crypto;
        r25 = r0;
        r0 = r28;
        r0 = r0.ks_enc;
        r26 = r0;
        r0 = r28;
        r0 = r0.ssc;
        r27 = r0;
        r25.init(r26, r27);
        r12 = r10.getData();
        r0 = r28;
        r0 = r0.crypto;	 Catch:{ AmCryptoException -> 0x01c6 }
        r25 = r0;
        r0 = r25;
        r9 = r0.decrypt(r12);	 Catch:{ AmCryptoException -> 0x01c6 }
        r0 = r9.length;
        r25 = r0;
        r25 = r25 + 2;
        r0 = r25;
        r0 = new byte[r0];
        r24 = r0;
        r25 = 0;
        r26 = 0;
        r0 = r9.length;
        r27 = r0;
        r0 = r25;
        r1 = r24;
        r2 = r26;
        r3 = r27;
        java.lang.System.arraycopy(r9, r0, r1, r2, r3);
        r18 = r16.getData();
        r25 = 0;
        r0 = r9.length;
        r26 = r0;
        r0 = r18;
        r0 = r0.length;
        r27 = r0;
        r0 = r18;
        r1 = r25;
        r2 = r24;
        r3 = r26;
        r4 = r27;
        java.lang.System.arraycopy(r0, r1, r2, r3, r4);
    L_0x01bc:
        r25 = new de.tsenger.androsmex.iso7816.ResponseAPDU;
        r0 = r25;
        r1 = r24;
        r0.<init>(r1);
        return r25;
    L_0x01c6:
        r19 = move-exception;
        r25 = new de.tsenger.androsmex.iso7816.SecureMessagingException;
        r0 = r25;
        r1 = r19;
        r0.<init>(r1);
        throw r25;
    L_0x01d1:
        r25 = r16.getData();
        r24 = r25.clone();
        r24 = (byte[]) r24;
        goto L_0x01bc;
    L_0x01dc:
        r19 = move-exception;
        r10 = r11;
        goto L_0x00ca;
    L_0x01e0:
        r19 = move-exception;
        r16 = r17;
        goto L_0x00ca;
    L_0x01e5:
        r19 = move-exception;
        r13 = r14;
        goto L_0x00ca;
        */
        throw new UnsupportedOperationException("Method not decompiled: de.tsenger.androsmex.iso7816.SecureMessaging.unwrap(de.tsenger.androsmex.iso7816.ResponseAPDU):de.tsenger.androsmex.iso7816.ResponseAPDU");
    }

    private DO87 buildDO87(byte[] data) throws SecureMessagingException {
        this.crypto.init(this.ks_enc, this.ssc);
        try {
            return new DO87(this.crypto.encrypt(data));
        } catch (Throwable e) {
            throw new SecureMessagingException(e);
        }
    }

    private DO8E buildDO8E(byte[] header, DO87 do87, DO97 do97) throws SecureMessagingException {
        ByteArrayOutputStream m = new ByteArrayOutputStream();
        if (do87 == null && do97 == null) {
            m.write(header);
        } else {
            try {
                m.write(this.crypto.addPadding(header));
            } catch (Throwable e) {
                throw new SecureMessagingException(e);
            }
        }
        if (do87 != null) {
            m.write(do87.getEncoded());
        }
        if (do97 != null) {
            m.write(do97.getEncoded());
        }
        this.crypto.init(this.ks_mac, this.ssc);
        return new DO8E(this.crypto.getMAC(m.toByteArray()));
    }

    private DO97 buildDO97(int le) {
        return new DO97(le);
    }

    private byte getAPDUStructure(CommandAPDU capdu) {
        byte[] cardcmd = capdu.getBytes();
        if (cardcmd.length == 4) {
            return (byte) 1;
        }
        if (cardcmd.length == 5) {
            return (byte) 2;
        }
        if (cardcmd.length == (cardcmd[4] & 255) + 5 && cardcmd[4] != (byte) 0) {
            return (byte) 3;
        }
        if (cardcmd.length == (cardcmd[4] & 255) + 6 && cardcmd[4] != (byte) 0) {
            return (byte) 4;
        }
        if (cardcmd.length == 7 && cardcmd[4] == (byte) 0) {
            return (byte) 5;
        }
        if (cardcmd.length == (((cardcmd[5] & 255) * 256) + 7) + (cardcmd[6] & 255) && cardcmd[4] == (byte) 0 && (cardcmd[5] != (byte) 0 || cardcmd[6] != (byte) 0)) {
            return (byte) 6;
        }
        if (cardcmd.length == (((cardcmd[5] & 255) * 256) + 9) + (cardcmd[6] & 255) && cardcmd[4] == (byte) 0 && (cardcmd[5] != (byte) 0 || cardcmd[6] != (byte) 0)) {
            return (byte) 7;
        }
        return (byte) 0;
    }

    private void incrementAtIndex(byte[] array, int index) {
        if (array[index] == (byte) -1) {
            array[index] = (byte) 0;
            if (index > 0) {
                incrementAtIndex(array, index - 1);
                return;
            }
            return;
        }
        array[index] = (byte) (array[index] + 1);
    }
}

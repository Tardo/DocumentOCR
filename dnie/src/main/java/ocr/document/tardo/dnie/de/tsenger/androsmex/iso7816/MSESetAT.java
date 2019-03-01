package de.tsenger.androsmex.iso7816;

import de.tsenger.androsmex.asn1.BSIObjectIdentifiers;
import de.tsenger.androsmex.asn1.CertificateHolderAuthorizationTemplate;
import de.tsenger.androsmex.asn1.DiscretionaryData;
import java.io.ByteArrayOutputStream;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERTaggedObject;

public class MSESetAT {
    public static final int KeyReference_CAN = 2;
    public static final int KeyReference_MRZ = 1;
    public static final int KeyReference_PIN = 3;
    public static final int KeyReference_PUK = 4;
    public static final int setAT_CA = 2;
    public static final int setAT_PACE = 1;
    public static final int setAT_TA = 3;
    private final byte CLASS = (byte) 0;
    private final byte INS = (byte) 34;
    private byte P1 = (byte) 0;
    private final byte P2 = (byte) -92;
    private byte[] do7F4C_CHAT = null;
    private byte[] do80CMR = null;
    private byte[] do83KeyName = null;
    private byte[] do83KeyReference = null;
    private byte[] do84PrivateKeyReference = null;
    private byte[] do91EphemeralPublicKEy = null;

    public void setAT(int at) {
        if (at == 1) {
            this.P1 = (byte) -63;
        }
        if (at == 2) {
            this.P1 = (byte) 65;
        }
        if (at == 3) {
            this.P1 = (byte) -127;
        }
    }

    public void setProtocol(String protocol) {
        this.do80CMR = new DERTaggedObject(false, 0, new DERObjectIdentifier(protocol)).getDEREncoded();
    }

    public void setKeyReference(int kr) {
        this.do83KeyReference = new DERTaggedObject(false, 3, new DERInteger(kr)).getDEREncoded();
    }

    public void setKeyReference(String kr) {
        this.do83KeyName = new DERTaggedObject(false, 3, new DEROctetString(kr.getBytes())).getDEREncoded();
    }

    public void setPrivateKeyReference(int pkr) {
        this.do84PrivateKeyReference = new DERTaggedObject(false, 4, new DERInteger(pkr)).getDEREncoded();
    }

    public void setAuxiliaryAuthenticatedData() throws UnsupportedOperationException {
        throw new UnsupportedOperationException("setAuxiliaryAuthenticationData not yet implemented!");
    }

    public void setEphemeralPublicKey(byte[] pubKey) {
        this.do91EphemeralPublicKEy = new DERTaggedObject(false, 17, new DEROctetString(pubKey)).getDEREncoded();
    }

    public void setCHAT(CertificateHolderAuthorizationTemplate chat) {
        this.do7F4C_CHAT = chat.getDEREncoded();
    }

    public CommandAPDU getCommandAPDU() {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        if (this.do80CMR != null) {
            bos.write(this.do80CMR, 0, this.do80CMR.length);
        }
        if (this.do83KeyReference != null) {
            bos.write(this.do83KeyReference, 0, this.do83KeyReference.length);
        }
        if (this.do83KeyName != null) {
            bos.write(this.do83KeyName, 0, this.do83KeyName.length);
        }
        if (this.do84PrivateKeyReference != null) {
            bos.write(this.do84PrivateKeyReference, 0, this.do84PrivateKeyReference.length);
        }
        if (this.do91EphemeralPublicKEy != null) {
            bos.write(this.do91EphemeralPublicKEy, 0, this.do91EphemeralPublicKEy.length);
        }
        if (this.do7F4C_CHAT != null) {
            bos.write(this.do7F4C_CHAT, 0, this.do7F4C_CHAT.length);
        }
        return new CommandAPDU(0, 34, this.P1, -92, bos.toByteArray());
    }

    public void setATChat() {
        setCHAT(new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_AT, new DiscretionaryData(new byte[]{(byte) 63, (byte) -1, (byte) -1, (byte) -1, (byte) -9})));
    }

    public void setISChat() {
        setCHAT(new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_IS, new DiscretionaryData((byte) 35)));
    }

    public void setSTChat() {
        setCHAT(new CertificateHolderAuthorizationTemplate(BSIObjectIdentifiers.id_ST, new DiscretionaryData((byte) 3)));
    }
}

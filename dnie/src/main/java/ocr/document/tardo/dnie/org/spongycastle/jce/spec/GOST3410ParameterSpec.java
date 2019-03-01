package org.spongycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.spongycastle.asn1.cryptopro.GOST3410NamedParameters;
import org.spongycastle.asn1.cryptopro.GOST3410ParamSetParameters;
import org.spongycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.spongycastle.jce.interfaces.GOST3410Params;

public class GOST3410ParameterSpec implements AlgorithmParameterSpec, GOST3410Params {
    private String digestParamSetOID;
    private String encryptionParamSetOID;
    private String keyParamSetOID;
    private GOST3410PublicKeyParameterSetSpec keyParameters;

    public GOST3410ParameterSpec(String keyParamSetID, String digestParamSetOID, String encryptionParamSetOID) {
        GOST3410ParamSetParameters ecP = null;
        try {
            ecP = GOST3410NamedParameters.getByOID(new DERObjectIdentifier(keyParamSetID));
        } catch (IllegalArgumentException e) {
            DERObjectIdentifier oid = GOST3410NamedParameters.getOID(keyParamSetID);
            if (oid != null) {
                keyParamSetID = oid.getId();
                ecP = GOST3410NamedParameters.getByOID(oid);
            }
        }
        if (ecP == null) {
            throw new IllegalArgumentException("no key parameter set for passed in name/OID.");
        }
        this.keyParameters = new GOST3410PublicKeyParameterSetSpec(ecP.getP(), ecP.getQ(), ecP.getA());
        this.keyParamSetOID = keyParamSetID;
        this.digestParamSetOID = digestParamSetOID;
        this.encryptionParamSetOID = encryptionParamSetOID;
    }

    public GOST3410ParameterSpec(String keyParamSetID, String digestParamSetOID) {
        this(keyParamSetID, digestParamSetOID, null);
    }

    public GOST3410ParameterSpec(String keyParamSetID) {
        this(keyParamSetID, CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet.getId(), null);
    }

    public GOST3410ParameterSpec(GOST3410PublicKeyParameterSetSpec spec) {
        this.keyParameters = spec;
        this.digestParamSetOID = CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet.getId();
        this.encryptionParamSetOID = null;
    }

    public String getPublicKeyParamSetOID() {
        return this.keyParamSetOID;
    }

    public GOST3410PublicKeyParameterSetSpec getPublicKeyParameters() {
        return this.keyParameters;
    }

    public String getDigestParamSetOID() {
        return this.digestParamSetOID;
    }

    public String getEncryptionParamSetOID() {
        return this.encryptionParamSetOID;
    }

    public boolean equals(Object o) {
        if (!(o instanceof GOST3410ParameterSpec)) {
            return false;
        }
        GOST3410ParameterSpec other = (GOST3410ParameterSpec) o;
        if (!this.keyParameters.equals(other.keyParameters) || !this.digestParamSetOID.equals(other.digestParamSetOID)) {
            return false;
        }
        if (this.encryptionParamSetOID == other.encryptionParamSetOID || (this.encryptionParamSetOID != null && this.encryptionParamSetOID.equals(other.encryptionParamSetOID))) {
            return true;
        }
        return false;
    }

    public int hashCode() {
        return (this.encryptionParamSetOID != null ? this.encryptionParamSetOID.hashCode() : 0) ^ (this.digestParamSetOID.hashCode() ^ this.keyParameters.hashCode());
    }

    public static GOST3410ParameterSpec fromPublicKeyAlg(GOST3410PublicKeyAlgParameters params) {
        if (params.getEncryptionParamSet() != null) {
            return new GOST3410ParameterSpec(params.getPublicKeyParamSet().getId(), params.getDigestParamSet().getId(), params.getEncryptionParamSet().getId());
        }
        return new GOST3410ParameterSpec(params.getPublicKeyParamSet().getId(), params.getDigestParamSet().getId());
    }
}
package de.tsenger.androsmex.asn1;

import de.tsenger.androsmex.crypto.DHStandardizedDomainParameters;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.DHParameters;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

public class DomainParameter {
    private DHParameters dhParameters = null;
    private ECParameterSpec ecSpec = null;

    public DomainParameter(int ref) {
        if (ref < 0 || ref > 18) {
            throw new UnsupportedOperationException("unsupported standardized Domain Parameters");
        }
        getParameters(ref);
    }

    public DomainParameter(AlgorithmIdentifier aid) {
        if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.standardizedDomainParameters.toString())) {
            getParameters(((DERInteger) aid.getParameters()).getPositiveValue().intValue());
        } else if (aid.getAlgorithm().toString().equals(BSIObjectIdentifiers.id_ecPublicKey)) {
            X9ECParameters x9ecp = new X9ECParameters((ASN1Sequence) aid.getParameters());
            this.ecSpec = new ECParameterSpec(x9ecp.getCurve(), x9ecp.getG(), x9ecp.getN());
        } else {
            throw new UnsupportedOperationException("unsupported Domain Parameters");
        }
    }

    private void getParameters(int dpref) {
        switch (dpref) {
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
                this.ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
                return;
            case 9:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("secp192r1");
                return;
            case 10:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("secp224r1");
                return;
            case 11:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp224r1");
                return;
            case 12:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
                return;
            case 13:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
                return;
            case 14:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp320r1");
                return;
            case 15:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
                return;
            case 16:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp384r1");
                return;
            case 17:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("brainpoolp512r1");
                return;
            case 18:
                this.ecSpec = ECNamedCurveTable.getParameterSpec("secp521r1");
                return;
            default:
                return;
        }
    }

    public String getDPType() {
        if (this.ecSpec != null) {
            return "ECDH";
        }
        if (this.dhParameters != null) {
            return "DH";
        }
        return null;
    }

    public ECParameterSpec getECParameter() {
        return this.ecSpec;
    }

    public DHParameters getDHParameter() {
        return this.dhParameters;
    }
}

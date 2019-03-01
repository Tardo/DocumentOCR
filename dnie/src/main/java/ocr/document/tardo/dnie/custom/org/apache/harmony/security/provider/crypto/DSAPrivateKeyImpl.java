package custom.org.apache.harmony.security.provider.crypto;

import custom.org.apache.harmony.security.PrivateKeyImpl;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.pkcs8.PrivateKeyInfo;
import custom.org.apache.harmony.security.utils.AlgNameMapper;
import custom.org.apache.harmony.security.x509.AlgorithmIdentifier;
import java.io.IOException;
import java.io.NotActiveException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class DSAPrivateKeyImpl extends PrivateKeyImpl implements DSAPrivateKey {
    private static final long serialVersionUID = -4716227614104950081L;
    /* renamed from: g */
    private BigInteger f205g;
    /* renamed from: p */
    private BigInteger f206p;
    private transient DSAParams params;
    /* renamed from: q */
    private BigInteger f207q;
    /* renamed from: x */
    private BigInteger f208x;

    public DSAPrivateKeyImpl(DSAPrivateKeySpec keySpec) {
        super("DSA");
        this.f205g = keySpec.getG();
        this.f206p = keySpec.getP();
        this.f207q = keySpec.getQ();
        AlgorithmIdentifier ai = new AlgorithmIdentifier(AlgNameMapper.map2OID("DSA"), new ThreeIntegerSequence(this.f206p.toByteArray(), this.f207q.toByteArray(), this.f205g.toByteArray()).getEncoded());
        this.f208x = keySpec.getX();
        setEncoding(new PrivateKeyInfo(0, ai, ASN1Integer.getInstance().encode(this.f208x.toByteArray()), null).getEncoded());
        this.params = new DSAParameterSpec(this.f206p, this.f207q, this.f205g);
    }

    public DSAPrivateKeyImpl(PKCS8EncodedKeySpec keySpec) throws InvalidKeySpecException {
        super("DSA");
        byte[] encoding = keySpec.getEncoded();
        try {
            PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) PrivateKeyInfo.ASN1.decode(encoding);
            try {
                this.f208x = new BigInteger((byte[]) ASN1Integer.getInstance().decode(privateKeyInfo.getPrivateKey()));
                AlgorithmIdentifier ai = privateKeyInfo.getAlgorithmIdentifier();
                try {
                    ThreeIntegerSequence threeInts = (ThreeIntegerSequence) ThreeIntegerSequence.ASN1.decode(ai.getParameters());
                    this.f206p = new BigInteger(threeInts.f14p);
                    this.f207q = new BigInteger(threeInts.f15q);
                    this.f205g = new BigInteger(threeInts.f13g);
                    this.params = new DSAParameterSpec(this.f206p, this.f207q, this.f205g);
                    setEncoding(encoding);
                    String alg = ai.getAlgorithm();
                    String algName = AlgNameMapper.map2AlgName(alg);
                    if (algName != null) {
                        alg = algName;
                    }
                    setAlgorithm(alg);
                } catch (Object e) {
                    throw new InvalidKeySpecException(Messages.getString("security.19B", e));
                }
            } catch (Object e2) {
                throw new InvalidKeySpecException(Messages.getString("security.19B", e2));
            }
        } catch (Object e22) {
            throw new InvalidKeySpecException(Messages.getString("security.19A", e22));
        }
    }

    public BigInteger getX() {
        return this.f208x;
    }

    public DSAParams getParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream in) throws NotActiveException, IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.params = new DSAParameterSpec(this.f206p, this.f207q, this.f205g);
    }
}

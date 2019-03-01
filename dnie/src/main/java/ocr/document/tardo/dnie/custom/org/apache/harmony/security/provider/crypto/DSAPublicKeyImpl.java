package custom.org.apache.harmony.security.provider.crypto;

import custom.org.apache.harmony.security.PublicKeyImpl;
import custom.org.apache.harmony.security.asn1.ASN1Integer;
import custom.org.apache.harmony.security.internal.nls.Messages;
import custom.org.apache.harmony.security.utils.AlgNameMapper;
import custom.org.apache.harmony.security.x509.AlgorithmIdentifier;
import custom.org.apache.harmony.security.x509.SubjectPublicKeyInfo;
import java.io.IOException;
import java.io.NotActiveException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class DSAPublicKeyImpl extends PublicKeyImpl implements DSAPublicKey {
    private static final long serialVersionUID = -2279672131310978336L;
    /* renamed from: g */
    private BigInteger f209g;
    /* renamed from: p */
    private BigInteger f210p;
    private transient DSAParams params;
    /* renamed from: q */
    private BigInteger f211q;
    /* renamed from: y */
    private BigInteger f212y;

    public DSAPublicKeyImpl(DSAPublicKeySpec keySpec) {
        super("DSA");
        this.f210p = keySpec.getP();
        this.f211q = keySpec.getQ();
        this.f209g = keySpec.getG();
        AlgorithmIdentifier ai = new AlgorithmIdentifier(AlgNameMapper.map2OID("DSA"), new ThreeIntegerSequence(this.f210p.toByteArray(), this.f211q.toByteArray(), this.f209g.toByteArray()).getEncoded());
        this.f212y = keySpec.getY();
        setEncoding(new SubjectPublicKeyInfo(ai, ASN1Integer.getInstance().encode(this.f212y.toByteArray())).getEncoded());
        this.params = new DSAParameterSpec(this.f210p, this.f211q, this.f209g);
    }

    public DSAPublicKeyImpl(X509EncodedKeySpec keySpec) throws InvalidKeySpecException {
        super("DSA");
        byte[] encoding = keySpec.getEncoded();
        try {
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) SubjectPublicKeyInfo.ASN1.decode(encoding);
            try {
                this.f212y = new BigInteger((byte[]) ASN1Integer.getInstance().decode(subjectPublicKeyInfo.getSubjectPublicKey()));
                AlgorithmIdentifier ai = subjectPublicKeyInfo.getAlgorithmIdentifier();
                try {
                    ThreeIntegerSequence threeInts = (ThreeIntegerSequence) ThreeIntegerSequence.ASN1.decode(ai.getParameters());
                    this.f210p = new BigInteger(threeInts.f14p);
                    this.f211q = new BigInteger(threeInts.f15q);
                    this.f209g = new BigInteger(threeInts.f13g);
                    this.params = new DSAParameterSpec(this.f210p, this.f211q, this.f209g);
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

    public BigInteger getY() {
        return this.f212y;
    }

    public DSAParams getParams() {
        return this.params;
    }

    private void readObject(ObjectInputStream in) throws NotActiveException, IOException, ClassNotFoundException {
        in.defaultReadObject();
        this.params = new DSAParameterSpec(this.f210p, this.f211q, this.f209g);
    }
}

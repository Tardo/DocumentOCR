package org.bouncycastle.operator.bc;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.operator.OperatorCreationException;

public class BcDefaultDigestProvider implements BcDigestProvider {
    public static final BcDigestProvider INSTANCE = new BcDefaultDigestProvider();
    private static final Map lookup = createTable();

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$1 */
    static class C01771 implements BcDigestProvider {
        C01771() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new SHA1Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$2 */
    static class C01782 implements BcDigestProvider {
        C01782() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new SHA224Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$3 */
    static class C01793 implements BcDigestProvider {
        C01793() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new SHA256Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$4 */
    static class C01804 implements BcDigestProvider {
        C01804() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new SHA384Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$5 */
    static class C01815 implements BcDigestProvider {
        C01815() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new SHA512Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$6 */
    static class C01826 implements BcDigestProvider {
        C01826() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new MD5Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$7 */
    static class C01837 implements BcDigestProvider {
        C01837() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new MD4Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$8 */
    static class C01848 implements BcDigestProvider {
        C01848() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new MD2Digest();
        }
    }

    /* renamed from: org.bouncycastle.operator.bc.BcDefaultDigestProvider$9 */
    static class C01859 implements BcDigestProvider {
        C01859() {
        }

        public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
            return new GOST3411Digest();
        }
    }

    private BcDefaultDigestProvider() {
    }

    private static Map createTable() {
        Map hashMap = new HashMap();
        hashMap.put(OIWObjectIdentifiers.idSHA1, new C01771());
        hashMap.put(NISTObjectIdentifiers.id_sha224, new C01782());
        hashMap.put(NISTObjectIdentifiers.id_sha256, new C01793());
        hashMap.put(NISTObjectIdentifiers.id_sha384, new C01804());
        hashMap.put(NISTObjectIdentifiers.id_sha512, new C01815());
        hashMap.put(PKCSObjectIdentifiers.md5, new C01826());
        hashMap.put(PKCSObjectIdentifiers.md4, new C01837());
        hashMap.put(PKCSObjectIdentifiers.md2, new C01848());
        hashMap.put(CryptoProObjectIdentifiers.gostR3411, new C01859());
        hashMap.put(TeleTrusTObjectIdentifiers.ripemd128, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
                return new RIPEMD128Digest();
            }
        });
        hashMap.put(TeleTrusTObjectIdentifiers.ripemd160, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
                return new RIPEMD160Digest();
            }
        });
        hashMap.put(TeleTrusTObjectIdentifiers.ripemd256, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) {
                return new RIPEMD256Digest();
            }
        });
        return Collections.unmodifiableMap(hashMap);
    }

    public ExtendedDigest get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
        BcDigestProvider bcDigestProvider = (BcDigestProvider) lookup.get(algorithmIdentifier.getAlgorithm());
        if (bcDigestProvider != null) {
            return bcDigestProvider.get(algorithmIdentifier);
        }
        throw new OperatorCreationException("cannot recognise digest");
    }
}

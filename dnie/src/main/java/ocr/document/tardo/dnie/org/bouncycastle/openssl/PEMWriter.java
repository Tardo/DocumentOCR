package org.bouncycastle.openssl;

import java.io.IOException;
import java.io.Writer;
import java.security.SecureRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

public class PEMWriter extends PemWriter {
    private String provider;

    public PEMWriter(Writer writer) {
        this(writer, BouncyCastleProvider.PROVIDER_NAME);
    }

    public PEMWriter(Writer writer, String str) {
        super(writer);
        this.provider = str;
    }

    public void writeObject(Object obj) throws IOException {
        writeObject(obj, null);
    }

    public void writeObject(Object obj, String str, char[] cArr, SecureRandom secureRandom) throws IOException {
        writeObject(obj, new JcePEMEncryptorBuilder(str).setSecureRandom(secureRandom).setProvider(this.provider).build(cArr));
    }

    public void writeObject(Object obj, PEMEncryptor pEMEncryptor) throws IOException {
        try {
            super.writeObject(new JcaMiscPEMGenerator(obj, pEMEncryptor));
        } catch (PemGenerationException e) {
            if (e.getCause() instanceof IOException) {
                throw ((IOException) e.getCause());
            }
            throw e;
        }
    }

    public void writeObject(PemObjectGenerator pemObjectGenerator) throws IOException {
        super.writeObject(pemObjectGenerator);
    }
}

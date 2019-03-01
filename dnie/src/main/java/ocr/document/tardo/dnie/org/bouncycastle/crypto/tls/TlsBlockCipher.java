package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class TlsBlockCipher implements TlsCipher {
    protected TlsContext context;
    protected BlockCipher decryptCipher;
    protected BlockCipher encryptCipher;
    protected byte[] randomData = new byte[256];
    protected TlsMac readMac;
    protected boolean useExplicitIV;
    protected TlsMac writeMac;

    public TlsBlockCipher(TlsContext tlsContext, BlockCipher blockCipher, BlockCipher blockCipher2, Digest digest, Digest digest2, int i) throws IOException {
        byte[] bArr;
        this.context = tlsContext;
        tlsContext.getSecureRandom().nextBytes(this.randomData);
        this.useExplicitIV = ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(tlsContext.getServerVersion().getEquivalentTLSVersion());
        int digestSize = ((i * 2) + digest.getDigestSize()) + digest2.getDigestSize();
        int blockSize = !this.useExplicitIV ? digestSize + (blockCipher.getBlockSize() + blockCipher2.getBlockSize()) : digestSize;
        byte[] calculateKeyBlock = TlsUtils.calculateKeyBlock(tlsContext, blockSize);
        TlsMac tlsMac = new TlsMac(tlsContext, digest, calculateKeyBlock, 0, digest.getDigestSize());
        int digestSize2 = 0 + digest.getDigestSize();
        TlsMac tlsMac2 = new TlsMac(tlsContext, digest2, calculateKeyBlock, digestSize2, digest2.getDigestSize());
        int digestSize3 = digest2.getDigestSize() + digestSize2;
        CipherParameters keyParameter = new KeyParameter(calculateKeyBlock, digestSize3, i);
        digestSize3 += i;
        CipherParameters keyParameter2 = new KeyParameter(calculateKeyBlock, digestSize3, i);
        int i2 = digestSize3 + i;
        if (this.useExplicitIV) {
            calculateKeyBlock = new byte[blockCipher.getBlockSize()];
            bArr = new byte[blockCipher2.getBlockSize()];
            digestSize3 = i2;
        } else {
            bArr = Arrays.copyOfRange(calculateKeyBlock, i2, blockCipher.getBlockSize() + i2);
            i2 += blockCipher.getBlockSize();
            byte[] copyOfRange = Arrays.copyOfRange(calculateKeyBlock, i2, blockCipher2.getBlockSize() + i2);
            digestSize3 = blockCipher2.getBlockSize() + i2;
            calculateKeyBlock = bArr;
            bArr = copyOfRange;
        }
        if (digestSize3 != blockSize) {
            throw new TlsFatalAlert((short) 80);
        }
        CipherParameters parametersWithIV;
        CipherParameters parametersWithIV2;
        if (tlsContext.isServer()) {
            this.writeMac = tlsMac2;
            this.readMac = tlsMac;
            this.encryptCipher = blockCipher2;
            this.decryptCipher = blockCipher;
            parametersWithIV = new ParametersWithIV(keyParameter2, bArr);
            parametersWithIV2 = new ParametersWithIV(keyParameter, calculateKeyBlock);
        } else {
            this.writeMac = tlsMac;
            this.readMac = tlsMac2;
            this.encryptCipher = blockCipher;
            this.decryptCipher = blockCipher2;
            parametersWithIV = new ParametersWithIV(keyParameter, calculateKeyBlock);
            parametersWithIV2 = new ParametersWithIV(keyParameter2, bArr);
        }
        this.encryptCipher.init(true, parametersWithIV);
        this.decryptCipher.init(false, parametersWithIV2);
    }

    protected int checkPaddingConstantTime(byte[] bArr, int i, int i2, int i3, int i4) {
        int i5;
        int i6;
        int i7 = i + i2;
        byte b = bArr[i7 - 1];
        int i8 = (b & 255) + 1;
        if ((!this.context.getServerVersion().isSSL() || i8 <= i3) && i4 + i8 <= i2) {
            i5 = i7 - i8;
            int i9 = 0;
            while (true) {
                i6 = i5 + 1;
                i5 = (byte) ((bArr[i5] ^ b) | i9);
                if (i6 >= i7) {
                    break;
                }
                i9 = i5;
                i5 = i6;
            }
            if (i5 != 0) {
                i6 = i8;
                i8 = 0;
            } else {
                i6 = i8;
            }
        } else {
            i5 = (byte) 0;
            i6 = 0;
            i8 = 0;
        }
        byte[] bArr2 = this.randomData;
        for (i6 = 
/*
Method generation error in method: org.bouncycastle.crypto.tls.TlsBlockCipher.checkPaddingConstantTime(byte[], int, int, int, int):int, dex: classes.dex
jadx.core.utils.exceptions.CodegenException: Error generate insn: PHI: (r1_4 'i6' int) = (r1_1 'i6' int), (r1_2 'i6' int), (r1_3 'i6' int) binds: {(r1_2 'i6' int)=B:17:0x0047, (r1_1 'i6' int)=B:14:0x003d, (r1_3 'i6' int)=B:5:0x001d} in method: org.bouncycastle.crypto.tls.TlsBlockCipher.checkPaddingConstantTime(byte[], int, int, int, int):int, dex: classes.dex
	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:226)
	at jadx.core.codegen.RegionGen.makeLoop(RegionGen.java:184)
	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:61)
	at jadx.core.codegen.RegionGen.makeSimpleRegion(RegionGen.java:87)
	at jadx.core.codegen.RegionGen.makeRegion(RegionGen.java:53)
	at jadx.core.codegen.MethodGen.addInstructions(MethodGen.java:187)
	at jadx.core.codegen.ClassGen.addMethod(ClassGen.java:320)
	at jadx.core.codegen.ClassGen.addMethods(ClassGen.java:257)
	at jadx.core.codegen.ClassGen.addClassBody(ClassGen.java:220)
	at jadx.core.codegen.ClassGen.addClassCode(ClassGen.java:110)
	at jadx.core.codegen.ClassGen.makeClass(ClassGen.java:75)
	at jadx.core.codegen.CodeGen.visit(CodeGen.java:12)
	at jadx.core.ProcessClass.process(ProcessClass.java:40)
	at jadx.api.JadxDecompiler.processClass(JadxDecompiler.java:282)
	at jadx.api.JavaClass.decompile(JavaClass.java:62)
	at jadx.api.JadxDecompiler.lambda$appendSourcesSave$0(JadxDecompiler.java:200)
	at jadx.api.JadxDecompiler$$Lambda$8/1122805102.run(Unknown Source)
Caused by: jadx.core.utils.exceptions.CodegenException: PHI can be used only in fallback mode
	at jadx.core.codegen.InsnGen.fallbackOnlyInsn(InsnGen.java:537)
	at jadx.core.codegen.InsnGen.makeInsnBody(InsnGen.java:509)
	at jadx.core.codegen.InsnGen.makeInsn(InsnGen.java:220)
	... 16 more

*/

        protected int chooseExtraPadBlocks(SecureRandom secureRandom, int i) {
            return Math.min(lowestBitSet(secureRandom.nextInt()), i);
        }

        public byte[] decodeCiphertext(long j, short s, byte[] bArr, int i, int i2) throws IOException {
            int blockSize = this.decryptCipher.getBlockSize();
            int size = this.readMac.getSize();
            int max = Math.max(blockSize, size + 1);
            if (this.useExplicitIV) {
                max += blockSize;
            }
            if (i2 < max) {
                throw new TlsFatalAlert((short) 50);
            } else if (i2 % blockSize != 0) {
                throw new TlsFatalAlert((short) 21);
            } else {
                int i3;
                int i4;
                if (this.useExplicitIV) {
                    this.decryptCipher.init(false, new ParametersWithIV(null, bArr, i, blockSize));
                    i3 = i + blockSize;
                    i4 = i2 - blockSize;
                } else {
                    i4 = i2;
                    i3 = i;
                }
                for (max = 0; max < i4; max += blockSize) {
                    this.decryptCipher.processBlock(bArr, i3 + max, bArr, i3 + max);
                }
                int checkPaddingConstantTime = checkPaddingConstantTime(bArr, i3, i4, blockSize, size);
                int i5 = (i4 - checkPaddingConstantTime) - size;
                if ((!Arrays.constantTimeAreEqual(this.readMac.calculateMacConstantTime(j, s, bArr, i3, i5, i4 - size, this.randomData), Arrays.copyOfRange(bArr, i3 + i5, (i3 + i5) + size)) ? 1 : null) != null || checkPaddingConstantTime == 0) {
                    throw new TlsFatalAlert((short) 20);
                }
                return Arrays.copyOfRange(bArr, i3, i3 + i5);
            }
        }

        public byte[] encodePlaintext(long j, short s, byte[] bArr, int i, int i2) {
            int i3;
            int blockSize = this.encryptCipher.getBlockSize();
            int size = this.writeMac.getSize();
            ProtocolVersion serverVersion = this.context.getServerVersion();
            int i4 = (blockSize - 1) - ((i2 + size) % blockSize);
            if (!(serverVersion.isDTLS() || serverVersion.isSSL())) {
                i4 += chooseExtraPadBlocks(this.context.getSecureRandom(), (255 - i4) / blockSize) * blockSize;
            }
            size = ((size + i2) + i4) + 1;
            int i5 = this.useExplicitIV ? size + blockSize : size;
            Object obj = new byte[i5];
            if (this.useExplicitIV) {
                Object obj2 = new byte[blockSize];
                this.context.getSecureRandom().nextBytes(obj2);
                this.encryptCipher.init(true, new ParametersWithIV(null, obj2));
                System.arraycopy(obj2, 0, obj, 0, blockSize);
                i3 = 0 + blockSize;
            } else {
                i3 = 0;
            }
            Object calculateMac = this.writeMac.calculateMac(j, s, bArr, i, i2);
            System.arraycopy(bArr, i, obj, i3, i2);
            System.arraycopy(calculateMac, 0, obj, i3 + i2, calculateMac.length);
            int length = (i3 + i2) + calculateMac.length;
            for (size = 0; size <= i4; size++) {
                obj[size + length] = (byte) i4;
            }
            while (i3 < i5) {
                this.encryptCipher.processBlock(obj, i3, obj, i3);
                i3 += blockSize;
            }
            return obj;
        }

        public int getPlaintextLimit(int i) {
            int blockSize = this.encryptCipher.getBlockSize();
            int size = ((i - (i % blockSize)) - this.writeMac.getSize()) - 1;
            return this.useExplicitIV ? size - blockSize : size;
        }

        public TlsMac getReadMac() {
            return this.readMac;
        }

        public TlsMac getWriteMac() {
            return this.writeMac;
        }

        protected int lowestBitSet(int i) {
            if (i == 0) {
                return 32;
            }
            int i2 = 0;
            while ((i & 1) == 0) {
                i2++;
                i >>= 1;
            }
            return i2;
        }
    }

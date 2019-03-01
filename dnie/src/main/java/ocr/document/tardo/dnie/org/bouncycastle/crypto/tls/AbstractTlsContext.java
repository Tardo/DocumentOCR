package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

abstract class AbstractTlsContext implements TlsContext {
    private ProtocolVersion clientVersion = null;
    private SecureRandom secureRandom;
    private SecurityParameters securityParameters;
    private ProtocolVersion serverVersion = null;
    private Object userObject = null;

    AbstractTlsContext(SecureRandom secureRandom, SecurityParameters securityParameters) {
        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
    }

    public byte[] exportKeyingMaterial(String str, byte[] bArr, int i) {
        SecurityParameters securityParameters = getSecurityParameters();
        Object clientRandom = securityParameters.getClientRandom();
        Object serverRandom = securityParameters.getServerRandom();
        int length = clientRandom.length + serverRandom.length;
        if (bArr != null) {
            length += bArr.length + 2;
        }
        Object obj = new byte[length];
        System.arraycopy(clientRandom, 0, obj, 0, clientRandom.length);
        int length2 = clientRandom.length + 0;
        System.arraycopy(serverRandom, 0, obj, length2, serverRandom.length);
        length2 += serverRandom.length;
        if (bArr != null) {
            TlsUtils.writeUint16(bArr.length, obj, length2);
            length2 += 2;
            System.arraycopy(bArr, 0, obj, length2, bArr.length);
            length2 += bArr.length;
        }
        if (length2 == length) {
            return TlsUtils.PRF(this, securityParameters.getMasterSecret(), str, obj, i);
        }
        throw new IllegalStateException("error in calculation of seed for export");
    }

    public ProtocolVersion getClientVersion() {
        return this.clientVersion;
    }

    public SecureRandom getSecureRandom() {
        return this.secureRandom;
    }

    public SecurityParameters getSecurityParameters() {
        return this.securityParameters;
    }

    public ProtocolVersion getServerVersion() {
        return this.serverVersion;
    }

    public Object getUserObject() {
        return this.userObject;
    }

    public void setClientVersion(ProtocolVersion protocolVersion) {
        this.clientVersion = protocolVersion;
    }

    public void setServerVersion(ProtocolVersion protocolVersion) {
        this.serverVersion = protocolVersion;
    }

    public void setUserObject(Object obj) {
        this.userObject = obj;
    }
}

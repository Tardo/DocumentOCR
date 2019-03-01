package custom.org.apache.harmony.security;

import com.jcraft.jzlib.JZlib;
import custom.org.apache.harmony.security.internal.nls.Messages;
import java.io.IOException;
import java.io.Reader;
import java.io.StreamTokenizer;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.crypto.tls.CipherSuite;

public class DefaultPolicyScanner {

    public static class GrantEntry {
        public String codebase;
        public Collection<PermissionEntry> permissions;
        public Collection<PrincipalEntry> principals;
        public String signers;

        public void addPrincipal(PrincipalEntry pe) {
            if (this.principals == null) {
                this.principals = new HashSet();
            }
            this.principals.add(pe);
        }
    }

    public static class InvalidFormatException extends Exception {
        private static final long serialVersionUID = 5789786270390222184L;

        public InvalidFormatException(String arg0) {
            super(arg0);
        }
    }

    public static class KeystoreEntry {
        public String type;
        public String url;
    }

    public static class PermissionEntry {
        public String actions;
        public String klass;
        public String name;
        public String signers;
    }

    public static class PrincipalEntry {
        public static final String WILDCARD = "*";
        public String klass;
        public String name;
    }

    protected StreamTokenizer configure(StreamTokenizer st) {
        st.slashSlashComments(true);
        st.slashStarComments(true);
        st.wordChars(95, 95);
        st.wordChars(36, 36);
        return st;
    }

    public void scanStream(Reader r, Collection<GrantEntry> grantEntries, List<KeystoreEntry> keystoreEntries) throws IOException, InvalidFormatException {
        StreamTokenizer st = configure(new StreamTokenizer(r));
        while (true) {
            switch (st.nextToken()) {
                case JZlib.Z_DATA_ERROR /*-3*/:
                    if (!Util.equalsIgnoreCase("keystore", st.sval)) {
                        if (!Util.equalsIgnoreCase("grant", st.sval)) {
                            handleUnexpectedToken(st, Messages.getString("security.89"));
                            break;
                        } else {
                            grantEntries.add(readGrantEntry(st));
                            break;
                        }
                    }
                    keystoreEntries.add(readKeystoreEntry(st));
                    break;
                case -1:
                    return;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    break;
                default:
                    handleUnexpectedToken(st);
                    break;
            }
        }
    }

    protected KeystoreEntry readKeystoreEntry(StreamTokenizer st) throws IOException, InvalidFormatException {
        KeystoreEntry ke = new KeystoreEntry();
        if (st.nextToken() == 34) {
            ke.url = st.sval;
            if (st.nextToken() == 34 || (st.ttype == 44 && st.nextToken() == 34)) {
                ke.type = st.sval;
            } else {
                st.pushBack();
            }
        } else {
            handleUnexpectedToken(st, Messages.getString("security.8A"));
        }
        return ke;
    }

    protected GrantEntry readGrantEntry(StreamTokenizer st) throws IOException, InvalidFormatException {
        GrantEntry ge = new GrantEntry();
        while (true) {
            switch (st.nextToken()) {
                case JZlib.Z_DATA_ERROR /*-3*/:
                    if (!Util.equalsIgnoreCase("signedby", st.sval)) {
                        if (!Util.equalsIgnoreCase("codebase", st.sval)) {
                            if (!Util.equalsIgnoreCase("principal", st.sval)) {
                                handleUnexpectedToken(st);
                                break;
                            }
                            ge.addPrincipal(readPrincipalEntry(st));
                            break;
                        } else if (st.nextToken() != 34) {
                            handleUnexpectedToken(st, Messages.getString("security.8C"));
                            break;
                        } else {
                            ge.codebase = st.sval;
                            break;
                        }
                    } else if (st.nextToken() != 34) {
                        handleUnexpectedToken(st, Messages.getString("security.8B"));
                        break;
                    } else {
                        ge.signers = st.sval;
                        continue;
                    }
                case 44:
                    break;
                case EACTags.SECURITY_ENVIRONMENT_TEMPLATE /*123*/:
                    ge.permissions = readPermissionEntries(st);
                    break;
                default:
                    st.pushBack();
                    break;
            }
            return ge;
        }
    }

    protected PrincipalEntry readPrincipalEntry(StreamTokenizer st) throws IOException, InvalidFormatException {
        PrincipalEntry pe = new PrincipalEntry();
        if (st.nextToken() == -3) {
            pe.klass = st.sval;
            st.nextToken();
        } else if (st.ttype == 42) {
            pe.klass = "*";
            st.nextToken();
        }
        if (st.ttype == 34) {
            StringBuilder sb = new StringBuilder();
            String[] elements = st.sval.split("[,]");
            int endIndex = elements.length - 1;
            for (int index = 0; index < endIndex; index++) {
                sb.append(elements[index].trim() + ',');
            }
            if (endIndex > -1) {
                sb.append(elements[endIndex].trim());
            }
            pe.name = sb.toString();
        } else if (st.ttype == 42) {
            pe.name = "*";
        } else {
            handleUnexpectedToken(st, Messages.getString("security.8D"));
        }
        return pe;
    }

    protected Collection<PermissionEntry> readPermissionEntries(StreamTokenizer st) throws IOException, InvalidFormatException {
        Collection<PermissionEntry> permissions = new HashSet();
        while (true) {
            switch (st.nextToken()) {
                case JZlib.Z_DATA_ERROR /*-3*/:
                    if (Util.equalsIgnoreCase("permission", st.sval)) {
                        PermissionEntry pe = new PermissionEntry();
                        int tok = st.nextToken();
                        if (tok == -3 || tok == 34) {
                            pe.klass = st.sval;
                            if (st.nextToken() == 34) {
                                pe.name = st.sval;
                                st.nextToken();
                            }
                            if (st.ttype == 44) {
                                st.nextToken();
                            }
                            if (st.ttype == 34) {
                                pe.actions = st.sval;
                                if (st.nextToken() == 44) {
                                    st.nextToken();
                                }
                            }
                            if (st.ttype != -3 || !Util.equalsIgnoreCase("signedby", st.sval)) {
                                st.pushBack();
                            } else if (st.nextToken() == 34) {
                                pe.signers = st.sval;
                            } else {
                                handleUnexpectedToken(st);
                            }
                            permissions.add(pe);
                            break;
                        }
                    }
                    handleUnexpectedToken(st, Messages.getString("security.8E"));
                    break;
                case CipherSuite.TLS_RSA_WITH_NULL_SHA256 /*59*/:
                    break;
                case EACTags.SECURE_MESSAGING_TEMPLATE /*125*/:
                    return permissions;
                default:
                    handleUnexpectedToken(st);
                    break;
            }
        }
    }

    protected String composeStatus(StreamTokenizer st) {
        return st.toString();
    }

    protected final void handleUnexpectedToken(StreamTokenizer st, String message) throws InvalidFormatException {
        throw new InvalidFormatException(Messages.getString("security.8F", composeStatus(st), message));
    }

    protected final void handleUnexpectedToken(StreamTokenizer st) throws InvalidFormatException {
        throw new InvalidFormatException(Messages.getString("security.90", composeStatus(st)));
    }
}

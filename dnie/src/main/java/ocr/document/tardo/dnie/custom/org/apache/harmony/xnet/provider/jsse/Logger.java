package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.PrintStream;
import java.security.AccessController;
import java.security.PrivilegedAction;

public class Logger {
    private static String[] names;

    /* renamed from: custom.org.apache.harmony.xnet.provider.jsse.Logger$1 */
    static class C00581 implements PrivilegedAction<String[]> {
        C00581() {
        }

        public String[] run() {
            return System.getProperty("jsse", "").split(",");
        }
    }

    public static class Stream extends PrintStream {
        private static int indent = 0;
        private final String prefix;

        public Stream(String name) {
            super(System.err);
            this.prefix = name + "[" + Thread.currentThread().getName() + "] ";
        }

        public void print(String msg) {
            for (int i = 0; i < indent; i++) {
                super.print("  ");
            }
            super.print(msg);
        }

        public void newIndent() {
            indent++;
        }

        public void endIndent() {
            indent--;
        }

        public void println(String msg) {
            print(this.prefix);
            super.println(msg);
        }

        public void print(byte[] data) {
            printAsHex(16, " ", "", data, 0, data.length);
        }

        public void print(byte[] data, int offset, int len) {
            printAsHex(16, " ", "", data, offset, len);
        }

        public void printAsHex(int perLine, String prefix, String delimiter, byte[] data) {
            printAsHex(perLine, prefix, delimiter, data, 0, data.length);
        }

        public void printAsHex(int perLine, String prefix, String delimiter, byte[] data, int offset, int len) {
            String line = "";
            for (int i = 0; i < len; i++) {
                String tail = Integer.toHexString(data[i + offset] & 255).toUpperCase();
                if (tail.length() == 1) {
                    tail = "0" + tail;
                }
                line = line + prefix + tail + delimiter;
                if ((i + 1) % perLine == 0) {
                    super.println(line);
                    line = "";
                }
            }
            super.println(line);
        }
    }

    static {
        try {
            names = (String[]) AccessController.doPrivileged(new C00581());
        } catch (Exception e) {
            names = new String[0];
        }
    }

    public static Stream getStream(String name) {
        for (String equals : names) {
            if (equals.equals(name)) {
                return new Stream(name);
            }
        }
        return null;
    }
}

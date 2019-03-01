package custom.org.apache.harmony.xnet.provider.jsse;

import java.io.IOException;
import java.io.InputStream;

public class SSLStreamedInput extends SSLInputStream {
    private InputStream in;

    public SSLStreamedInput(InputStream in) {
        this.in = in;
    }

    public int available() throws IOException {
        return this.in.available();
    }

    public int read() throws IOException {
        int res = this.in.read();
        if (res >= 0) {
            return res;
        }
        throw new EndOfSourceException();
    }
}

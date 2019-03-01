package es.gob.jmulticard.apdu;

import java.io.ByteArrayOutputStream;

public abstract class CommandApdu extends Apdu {
    private final byte[] body;
    private final byte cla;
    private final byte ins;
    private Integer le;
    private final byte p1;
    private final byte p2;

    protected CommandApdu(byte cla, byte ins, byte param1, byte param2, byte[] data, Integer ne) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.cla = cla;
        baos.write(cla);
        this.ins = ins;
        baos.write(ins);
        this.p1 = param1;
        baos.write(param1);
        this.p2 = param2;
        baos.write(param2);
        if (data == null) {
            this.body = null;
        } else {
            this.body = new byte[data.length];
            System.arraycopy(data, 0, this.body, 0, data.length);
            baos.write(Integer.valueOf(String.valueOf(this.body.length)).byteValue());
            if (this.body.length > 0) {
                try {
                    baos.write(this.body);
                } catch (Exception e) {
                    throw new IllegalArgumentException("No se pueden tratar los datos de la APDU: " + e, e);
                }
            }
        }
        this.le = ne;
        if (ne != null) {
            baos.write(ne.byteValue());
        }
        setBytes(baos.toByteArray());
    }

    public byte getP1() {
        return this.p1;
    }

    public byte getP2() {
        return this.p2;
    }

    public byte getCla() {
        return this.cla;
    }

    public byte getIns() {
        return this.ins;
    }

    public byte[] getData() {
        if (this.body == null) {
            return null;
        }
        byte[] out = new byte[this.body.length];
        System.arraycopy(this.body, 0, out, 0, this.body.length);
        return out;
    }

    public Integer getLe() {
        return this.le;
    }

    public void setLe(int le) {
        this.le = Integer.valueOf(String.valueOf(le));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(this.cla);
        baos.write(this.ins);
        baos.write(this.p1);
        baos.write(this.p2);
        if (this.body != null && this.body.length > 0) {
            try {
                baos.write(this.body);
            } catch (Exception e) {
                throw new IllegalArgumentException("No se pueden tratar los datos de la APDU: " + e, e);
            }
        }
        baos.write(le);
        setBytes(baos.toByteArray());
    }
}

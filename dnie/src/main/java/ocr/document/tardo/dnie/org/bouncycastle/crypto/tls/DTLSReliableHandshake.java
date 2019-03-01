package org.bouncycastle.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import org.bouncycastle.util.Integers;

class DTLSReliableHandshake {
    private static final int MAX_RECEIVE_AHEAD = 10;
    private Hashtable currentInboundFlight = new Hashtable();
    private TlsHandshakeHash hash = new DeferredHash();
    private int message_seq = 0;
    private int next_receive_seq = 0;
    private Vector outboundFlight = new Vector();
    private Hashtable previousInboundFlight = null;
    private final DTLSRecordLayer recordLayer;
    private boolean sending = true;

    static class Message {
        private final byte[] body;
        private final int message_seq;
        private final short msg_type;

        private Message(int i, short s, byte[] bArr) {
            this.message_seq = i;
            this.msg_type = s;
            this.body = bArr;
        }

        public byte[] getBody() {
            return this.body;
        }

        public int getSeq() {
            return this.message_seq;
        }

        public short getType() {
            return this.msg_type;
        }
    }

    /* renamed from: org.bouncycastle.crypto.tls.DTLSReliableHandshake$1 */
    class C01561 implements DTLSHandshakeRetransmit {
        C01561() throws IOException {
        }

        public void receivedHandshakeRecord(int i, byte[] bArr, int i2, int i3) throws IOException {
            if (i3 >= 12) {
                int readUint24 = TlsUtils.readUint24(bArr, i2 + 9);
                if (i3 == readUint24 + 12) {
                    int readUint16 = TlsUtils.readUint16(bArr, i2 + 4);
                    if (readUint16 < DTLSReliableHandshake.this.next_receive_seq) {
                        short readUint8 = TlsUtils.readUint8(bArr, i2);
                        if (i == (readUint8 == (short) 20 ? 1 : 0)) {
                            int readUint242 = TlsUtils.readUint24(bArr, i2 + 1);
                            int readUint243 = TlsUtils.readUint24(bArr, i2 + 6);
                            if (readUint243 + readUint24 <= readUint242) {
                                DTLSReassembler dTLSReassembler = (DTLSReassembler) DTLSReliableHandshake.this.currentInboundFlight.get(Integers.valueOf(readUint16));
                                if (dTLSReassembler != null) {
                                    dTLSReassembler.contributeFragment(readUint8, readUint242, bArr, i2 + 12, readUint243, readUint24);
                                    if (DTLSReliableHandshake.checkAll(DTLSReliableHandshake.this.currentInboundFlight)) {
                                        DTLSReliableHandshake.this.resendOutboundFlight();
                                        DTLSReliableHandshake.resetAll(DTLSReliableHandshake.this.currentInboundFlight);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    DTLSReliableHandshake(TlsContext tlsContext, DTLSRecordLayer dTLSRecordLayer) {
        this.recordLayer = dTLSRecordLayer;
        this.hash.init(tlsContext);
    }

    private static boolean checkAll(Hashtable hashtable) {
        Enumeration elements = hashtable.elements();
        while (elements.hasMoreElements()) {
            if (((DTLSReassembler) elements.nextElement()).getBodyIfComplete() == null) {
                return false;
            }
        }
        return true;
    }

    private void checkInboundFlight() {
        Enumeration keys = this.currentInboundFlight.keys();
        while (keys.hasMoreElements()) {
            if (((Integer) keys.nextElement()).intValue() >= this.next_receive_seq) {
            }
        }
    }

    private void prepareInboundFlight() {
        resetAll(this.currentInboundFlight);
        this.previousInboundFlight = this.currentInboundFlight;
        this.currentInboundFlight = new Hashtable();
    }

    private void resendOutboundFlight() throws IOException {
        this.recordLayer.resetWriteEpoch();
        for (int i = 0; i < this.outboundFlight.size(); i++) {
            writeMessage((Message) this.outboundFlight.elementAt(i));
        }
    }

    private static void resetAll(Hashtable hashtable) {
        Enumeration elements = hashtable.elements();
        while (elements.hasMoreElements()) {
            ((DTLSReassembler) elements.nextElement()).reset();
        }
    }

    private Message updateHandshakeMessagesDigest(Message message) throws IOException {
        if (message.getType() != (short) 0) {
            byte[] body = message.getBody();
            byte[] bArr = new byte[12];
            TlsUtils.writeUint8(message.getType(), bArr, 0);
            TlsUtils.writeUint24(body.length, bArr, 1);
            TlsUtils.writeUint16(message.getSeq(), bArr, 4);
            TlsUtils.writeUint24(0, bArr, 6);
            TlsUtils.writeUint24(body.length, bArr, 9);
            this.hash.update(bArr, 0, bArr.length);
            this.hash.update(body, 0, body.length);
        }
        return message;
    }

    private void writeHandshakeFragment(Message message, int i, int i2) throws IOException {
        OutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        TlsUtils.writeUint8(message.getType(), byteArrayOutputStream);
        TlsUtils.writeUint24(message.getBody().length, byteArrayOutputStream);
        TlsUtils.writeUint16(message.getSeq(), byteArrayOutputStream);
        TlsUtils.writeUint24(i, byteArrayOutputStream);
        TlsUtils.writeUint24(i2, byteArrayOutputStream);
        byteArrayOutputStream.write(message.getBody(), i, i2);
        byte[] toByteArray = byteArrayOutputStream.toByteArray();
        this.recordLayer.send(toByteArray, 0, toByteArray.length);
    }

    private void writeMessage(Message message) throws IOException {
        int sendLimit = this.recordLayer.getSendLimit() - 12;
        if (sendLimit < 1) {
            throw new TlsFatalAlert((short) 80);
        }
        int length = message.getBody().length;
        int i = 0;
        do {
            int min = Math.min(length - i, sendLimit);
            writeHandshakeFragment(message, i, min);
            i += min;
        } while (i < length);
    }

    void finish() {
        DTLSHandshakeRetransmit dTLSHandshakeRetransmit = null;
        if (!this.sending) {
            checkInboundFlight();
        } else if (this.currentInboundFlight != null) {
            dTLSHandshakeRetransmit = new C01561();
        }
        this.recordLayer.handshakeSuccessful(dTLSHandshakeRetransmit);
    }

    byte[] getCurrentHash() {
        TlsHandshakeHash fork = this.hash.fork();
        byte[] bArr = new byte[fork.getDigestSize()];
        fork.doFinal(bArr, 0);
        return bArr;
    }

    void notifyHelloComplete() {
        this.hash = this.hash.commit();
    }

    Message receiveMessage() throws IOException {
        byte[] bodyIfComplete;
        Object obj = null;
        if (this.sending) {
            this.sending = false;
            prepareInboundFlight();
        }
        DTLSReassembler dTLSReassembler = (DTLSReassembler) this.currentInboundFlight.get(Integers.valueOf(this.next_receive_seq));
        if (dTLSReassembler != null) {
            bodyIfComplete = dTLSReassembler.getBodyIfComplete();
            if (bodyIfComplete != null) {
                this.previousInboundFlight = null;
                int i = this.next_receive_seq;
                this.next_receive_seq = i + 1;
                return updateHandshakeMessagesDigest(new Message(i, dTLSReassembler.getType(), bodyIfComplete));
            }
        }
        int i2 = 1000;
        while (true) {
            int i3;
            int receiveLimit = this.recordLayer.getReceiveLimit();
            if (obj == null || obj.length < receiveLimit) {
                obj = new byte[receiveLimit];
                i3 = i2;
            } else {
                i3 = i2;
            }
            while (true) {
                i2 = this.recordLayer.receive(obj, 0, receiveLimit, i3);
                if (i2 < 0) {
                    continue;
                    break;
                } else if (i2 >= 12) {
                    try {
                        int readUint24 = TlsUtils.readUint24(obj, 9);
                        if (i2 == readUint24 + 12) {
                            int readUint16 = TlsUtils.readUint16(obj, 4);
                            if (readUint16 <= this.next_receive_seq + 10) {
                                short readUint8 = TlsUtils.readUint8(obj, 0);
                                int readUint242 = TlsUtils.readUint24(obj, 1);
                                int readUint243 = TlsUtils.readUint24(obj, 6);
                                if (readUint243 + readUint24 > readUint242) {
                                    continue;
                                } else if (readUint16 >= this.next_receive_seq) {
                                    dTLSReassembler = (DTLSReassembler) this.currentInboundFlight.get(Integers.valueOf(readUint16));
                                    if (dTLSReassembler == null) {
                                        dTLSReassembler = new DTLSReassembler(readUint8, readUint242);
                                        this.currentInboundFlight.put(Integers.valueOf(readUint16), dTLSReassembler);
                                    }
                                    dTLSReassembler.contributeFragment(readUint8, readUint242, obj, 12, readUint243, readUint24);
                                    if (readUint16 == this.next_receive_seq) {
                                        bodyIfComplete = dTLSReassembler.getBodyIfComplete();
                                        if (bodyIfComplete != null) {
                                            this.previousInboundFlight = null;
                                            i = this.next_receive_seq;
                                            this.next_receive_seq = i + 1;
                                            return updateHandshakeMessagesDigest(new Message(i, dTLSReassembler.getType(), bodyIfComplete));
                                        }
                                    } else {
                                        continue;
                                    }
                                } else if (this.previousInboundFlight != null) {
                                    dTLSReassembler = (DTLSReassembler) this.previousInboundFlight.get(Integers.valueOf(readUint16));
                                    if (dTLSReassembler != null) {
                                        dTLSReassembler.contributeFragment(readUint8, readUint242, obj, 12, readUint243, readUint24);
                                        if (checkAll(this.previousInboundFlight)) {
                                            resendOutboundFlight();
                                            i2 = Math.min(i3 * 2, 60000);
                                            try {
                                                resetAll(this.previousInboundFlight);
                                                i3 = i2;
                                            } catch (IOException e) {
                                                i3 = i2;
                                            }
                                        }
                                    }
                                    i2 = i3;
                                    i3 = i2;
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    } catch (IOException e2) {
                    }
                }
            }
            resendOutboundFlight();
            i2 = Math.min(i3 * 2, 60000);
        }
    }

    void resetHandshakeMessagesDigest() {
        this.hash.reset();
    }

    void sendMessage(short s, byte[] bArr) throws IOException {
        if (!this.sending) {
            checkInboundFlight();
            this.sending = true;
            this.outboundFlight.removeAllElements();
        }
        int i = this.message_seq;
        this.message_seq = i + 1;
        Message message = new Message(i, s, bArr);
        this.outboundFlight.addElement(message);
        writeMessage(message);
        updateHandshakeMessagesDigest(message);
    }
}

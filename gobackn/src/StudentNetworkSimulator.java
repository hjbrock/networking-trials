public class StudentNetworkSimulator extends NetworkSimulator
{
    /*
     * Predefined Constants (static member variables):
     *
     *   int MAXDATASIZE : the maximum size of the Message data and
     *                     Packet payload
     *
     *   int A           : a predefined integer that represents entity A
     *   int B           : a predefined integer that represents entity B
     *
     *
     * Predefined Member Methods:
     *
     *  void stopTimer(int entity): 
     *       Stops the timer running at "entity" [A or B]
     *  void startTimer(int entity, double increment): 
     *       Starts a timer running at "entity" [A or B], which will expire in
     *       "increment" time units, causing the interrupt handler to be
     *       called.  You should only call this with A.
     *  void toLayer3(int callingEntity, Packet p)
     *       Puts the packet "p" into the network from "callingEntity" [A or B]
     *  void toLayer5(int entity, String dataSent)
     *       Passes "dataSent" up to layer 5 from "entity" [A or B]
     *  double getTime()
     *       Returns the current time in the simulator.  Might be useful for
     *       debugging.
     *  void printEventList()
     *       Prints the current event list to stdout.  Might be useful for
     *       debugging, but probably not.
     *
     *
     *  Predefined Classes:
     *
     *  Message: Used to encapsulate a message coming from layer 5
     *    Constructor:
     *      Message(String inputData): 
     *          creates a new Message containing "inputData"
     *    Methods:
     *      boolean setData(String inputData):
     *          sets an existing Message's data to "inputData"
     *          returns true on success, false otherwise
     *      String getData():
     *          returns the data contained in the message
     *  Packet: Used to encapsulate a packet
     *    Constructors:
     *      Packet (Packet p):
     *          creates a new Packet that is a copy of "p"
     *      Packet (int seq, int ack, int check, String newPayload)
     *          creates a new Packet with a sequence field of "seq", an
     *          ack field of "ack", a checksum field of "check", and a
     *          payload of "newPayload"
     *      Packet (int seq, int ack, int check)
     *          chreate a new Packet with a sequence field of "seq", an
     *          ack field of "ack", a checksum field of "check", and
     *          an empty payload
     *    Methods:
     *      boolean setSeqnum(int n)
     *          sets the Packet's sequence field to "n"
     *          returns true on success, false otherwise
     *      boolean setAcknum(int n)
     *          sets the Packet's ack field to "n"
     *          returns true on success, false otherwise
     *      boolean setChecksum(int n)
     *          sets the Packet's checksum to "n"
     *          returns true on success, false otherwise
     *      boolean setPayload(String newPayload)
     *          sets the Packet's payload to "newPayload"
     *          returns true on success, false otherwise
     *      int getSeqnum()
     *          returns the contents of the Packet's sequence field
     *      int getAcknum()
     *          returns the contents of the Packet's ack field
     *      int getChecksum()
     *          returns the checksum of the Packet
     *      int getPayload()
     *          returns the Packet's payload
     *
     */

    // Add any necessary class variables here.  Remember, you cannot use
    // these variables to send messages error free!  They can only hold
    // state information for A or B.
    // Also add any necessary methods (e.g. checksum of a String)

    // Global state variables
    private int packetsPresumedLost = 0;
    private int packetsCorrupted = 0;
    private int packetsSent = 0;
    private int packetsReceived = 0;
    private int originalPacketsSent = 0;
    private int packetsACKed = 0;
    private int trace;
    private final int bufferSize = 50;

    // State variables for A
    private Packet[] buffer;
    private final int windowSize = 8;
    private int nextSeqNum;
    private int base;
    private double timeSent;
    private double totalRTT;

    // State variables for B
    private int expectedSeqNum;
    private int lastAcked;

    // This is the constructor.  Don't touch!
    public StudentNetworkSimulator(int numMessages,
                                   double loss,
                                   double corrupt,
                                   double avgDelay,
                                   int trace,
                                   long seed)
    {
        super(numMessages, loss, corrupt, avgDelay, trace, seed);
        this.trace = trace;
    }

    /**
     * Create a checksum using the given values
     * @param seqNum
     * @param ackNum
     * @param payload
     * @return Returns a checksum.
     */
    private int createCheckSum(int seqNum, int ackNum, String payload) {
        int checksum = seqNum + ackNum;
        for (int i = 0; i < payload.length(); i++)
            checksum += payload.charAt(i);
        return checksum;
    }

    /**
     * Checks if a packet is corrupt
     * @param p
     * @return Returns true if the packet is corrupt, false otherwise
     */
    private boolean isCorrupt(Packet p) {
        int actualChecksum = createCheckSum(p.getSeqnum(), p.getAcknum(), p.getPayload());
        return actualChecksum != p.getChecksum();
    }

    /**
     * Adds a message to the buffer
     * @return true if the buffer is full
     */
    private boolean addToBuffer(Message m) {
        for (int i = base; (i % bufferSize) != ((base+windowSize)%bufferSize); i++) {
            int j = i % bufferSize;
            if (buffer[j] == null) {
                int checksum = createCheckSum(j, -1, m.getData());
                Packet p = new Packet(j, -1, checksum, m.getData());
                buffer[j] = p;
                log("A: item added to buffer at index " + j, 1);
                return true;
            }
        }
        return false;
    }

    /**
     * Sends the next available packet
     */
    private void sendNext() {
        if (buffer[nextSeqNum] == null) {
            log("A: Nothing to send", 1);
            return;
        }

        String msg = "A: Sent packet ("+buffer[nextSeqNum].toString()+")";
        toLayer3(0, buffer[nextSeqNum]);
        if (base == nextSeqNum) {
            startTimer(0,20);
            timeSent = getTime();
            msg += " and started timer";
        }
        log(msg, 1);
        nextSeqNum = (nextSeqNum+1) % bufferSize;
        packetsSent++;
        originalPacketsSent++;
    }

    /**
     * Resends all packets in the window
     */
    private void sendAll() {
        for (int i = base; (i%bufferSize) != nextSeqNum; i++) {
            toLayer3(0, buffer[i%bufferSize]);
            log("A: Sent packet (" + buffer[i % bufferSize].toString() + ")", 1);
            packetsSent++;
        }
    }

    /**
     * Checks if a sequence number is in the sending window
     * @param index the number
     * @return true if it's within the sending window
     */
    private boolean isInWindow(int index) {
        int max = base + windowSize;
        if (index < 0 || index >= bufferSize)
            return false;
        if (index == base) {
            return true;
        }
        else if (index > base) {
            return index < (base + windowSize);
        }
        else {
            return index < ((base + windowSize) % bufferSize);
        }
    }

    // This routine will be called whenever the upper layer at the sender [A]
    // has a message to send.  It is the job of your protocol to insure that
    // the data in such a message is delivered in-order, and correctly, to
    // the receiving upper layer.
    protected void aOutput(Message message)
    {
        log("A: received packet from Layer 5", 1);

        // ignore new data if the buffer is full
        if (!addToBuffer(message)) {
            log("A: Buffer full. Ignoring data from layer 5.",1);
            return;
        }

        if (isInWindow(nextSeqNum)) {
            sendNext();
        } else {
            log("A: Next sequence num not in window: " + nextSeqNum, 1);
        }
    }
    
    // This routine will be called whenever a packet sent from the B-side 
    // (i.e. as a result of a toLayer3() being done by a B-side procedure)
    // arrives at the A-side.  "packet" is the (possibly corrupted) packet
    // sent from the B-side.
    protected void aInput(Packet packet)
    {
        boolean corrupt = isCorrupt(packet);
        packetsReceived++;

        String msg = "A received a ";
        msg += corrupt ? "corrupt" : "non-corrupt";
        msg += " packet ("+packet.toString()
                + "); expected ack num was " + base;
        log(msg, 1);

        boolean bad = corrupt || (!isInWindow(packet.getAcknum()));
        if (!bad) {
            // cumulative ack
            for (int i = base; (i % bufferSize) != ((packet.getAcknum()+1)%bufferSize); i++) {
                buffer[i%bufferSize] = null;
            }
            base = (packet.getAcknum() + 1) % bufferSize;
            if (base == nextSeqNum) {
                log("A: stopping timer", 1);
                stopTimer(0);
                totalRTT += getTime() - timeSent;
            }
            sendNext();
        }
        if (corrupt)
            packetsCorrupted++;
    }
    
    // This routine will be called when A's timer expires (thus generating a 
    // timer interrupt). You'll probably want to use this routine to control 
    // the retransmission of packets. See startTimer() and stopTimer(), above,
    // for how the timer is started and stopped. 
    protected void aTimerInterrupt()
    {
        log("A: TIMER INTERRUPT. Resending all packets in the window and restarting timer.", 1);
        sendAll();
        startTimer(0, 20);
        timeSent = getTime();
        packetsPresumedLost++;
    }
    
    // This routine will be called once, before any of your other A-side 
    // routines are called. It can be used to do any required
    // initialization (e.g. of member variables you add to control the state
    // of entity A).
    protected void aInit()
    {
        buffer = new Packet[bufferSize];
        base = 0;
        nextSeqNum = 0;
        totalRTT = 0;
        timeSent = 0;
    }
    
    // This routine will be called whenever a packet sent from the B-side 
    // (i.e. as a result of a toLayer3() being done by an A-side procedure)
    // arrives at the B-side.  "packet" is the (possibly corrupted) packet
    // sent from the A-side.
    protected void bInput(Packet packet)
    {
        boolean corrupt = isCorrupt(packet);
        packetsReceived++;

        String msg = "B: received a ";
        msg += corrupt ? "corrupt" : "non-corrupt";
        msg += " packet (" + packet.toString()
                + "); expected seq num was " + expectedSeqNum;
        log(msg, 1);

        boolean bad = corrupt || (packet.getSeqnum() != expectedSeqNum);
        Packet ack;
        int checksum;
        if (bad) {
            checksum = createCheckSum(0, lastAcked, " ");
            ack = new Packet(0, lastAcked, checksum, " ");
            log("B: sending duplicate ack (" + ack.toString() + ")", 1);
            packetsSent++;
            if (corrupt)
                packetsCorrupted++;
        }
        else {
            log("B: sending ack ("+packet.toString() + ") and delivering data to layer 5", 1);
            checksum = createCheckSum(0, expectedSeqNum, " ");
            ack = new Packet(0, expectedSeqNum, checksum, " ");
            lastAcked = expectedSeqNum;
            expectedSeqNum = (expectedSeqNum + 1) % bufferSize;
            toLayer5(1, packet.getPayload());
            packetsSent++;
            packetsACKed++;
        }
        toLayer3(1, ack);
    }
    
    // This routine will be called once, before any of your other B-side 
    // routines are called. It can be used to do any required
    // initialization (e.g. of member variables you add to control the state
    // of entity B).
    protected void bInit()
    {
        expectedSeqNum = 0;
        lastAcked = bufferSize - 1;
    }

    public void printStats() {
        System.out.println("\n----------------------------------------------------------------------------------\n" +
                           "| Run statistics: \n" +
                           "| Total packets sent (including acks and retransmissions): " + packetsSent +
                           "\n| Original packets sent: " + originalPacketsSent +
                           "\n| Retransmissions: " + packetsPresumedLost +
                           "\n| Packets lost: "+(packetsSent-packetsReceived) + " = " +
                                (packetsSent-packetsReceived)/(double)packetsSent +
                           "\n| Packets corrupted: " + packetsCorrupted + " = " +
                                packetsCorrupted/(double)packetsSent +
                           "\n| Packets ACKed: "+packetsACKed+
                           "\n| Average RTT: "+totalRTT/originalPacketsSent);
    }

    protected void log(String message, int logLevel){
        if (logLevel <= trace) {
            System.out.println("At " + getTime() + " - " + message);
        }
    }
}

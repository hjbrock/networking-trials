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

    // State variables for A
    private boolean packetInTransit;
    private Packet lastSentPacket;
    private int nextSeqNum;
    private double timeSent;
    private double totalRTT;

    // State variables for B
    private int expectedSeqNum;
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

    // This routine will be called whenever the upper layer at the sender [A]
    // has a message to send.  It is the job of your protocol to insure that
    // the data in such a message is delivered in-order, and correctly, to
    // the receiving upper layer.
    protected void aOutput(Message message)
    {
        log("A: received packet from Layer 5", 1);
        // ignore new data if we still have an un-acked packet
        if (packetInTransit) {
            log("A: Un-ACKed packet in transit. Ignoring data from layer 5.",1);
            return;
        }

        int checksum = createCheckSum(nextSeqNum, -1, message.getData());
        Packet p = new Packet(nextSeqNum, -1, checksum, message.getData());
        toLayer3(0, p);
        startTimer(0, 20);
        timeSent = getTime();
        nextSeqNum = (nextSeqNum+1) % 2;
        lastSentPacket = p;
        packetInTransit = true;
        packetsSent++;
        originalPacketsSent++;
        log("A: Sent packet ("+p.toString()+") and started timer", 1);
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
                + "); expected ack num was " + lastSentPacket.getSeqnum();
        log(msg, 1);

        boolean bad = corrupt || (packet.getAcknum() != lastSentPacket.getSeqnum());
        int checksum;
        if (!bad) {
            log("A: stopping timer", 1);
            stopTimer(0);
            totalRTT += getTime() - timeSent;
            packetInTransit = false;
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
        log("A: TIMER INTERRUPT. Resending ("+lastSentPacket.toString()+") and restarting timer.", 1);
        toLayer3(0, lastSentPacket);
        startTimer(0, 20);
        timeSent = getTime();
        packetsPresumedLost++;
        packetsSent++;
    }
    
    // This routine will be called once, before any of your other A-side 
    // routines are called. It can be used to do any required
    // initialization (e.g. of member variables you add to control the state
    // of entity A).
    protected void aInit()
    {
        packetInTransit = false;
        nextSeqNum = 0;
        lastSentPacket = null;
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
            int lastSeqNum = (expectedSeqNum + 1) % 2;
            checksum = createCheckSum(0, lastSeqNum, " ");
            ack = new Packet(0, lastSeqNum, checksum, " ");
            log("B: sending duplicate ack (" + ack.toString() + ")", 1);
            packetsSent++;
            if (corrupt)
                packetsCorrupted++;
        }
        else {
            log("B: sending ack ("+packet.toString() + ") and delivering data to layer 5", 1);
            checksum = createCheckSum(0, expectedSeqNum, " ");
            ack = new Packet(0, expectedSeqNum, checksum, " ");
            expectedSeqNum = (expectedSeqNum + 1) % 2;
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
                                packetsCorrupted/(double)packetsSent + "%" +
                           "\n| Packets ACKed: "+packetsACKed+
                           "\n| Average RTT: "+totalRTT/originalPacketsSent);
    }

    protected void log(String message, int logLevel){
        if (logLevel <= trace) {
            System.out.println("At " + getTime() + " - " + message);
        }
    }
}

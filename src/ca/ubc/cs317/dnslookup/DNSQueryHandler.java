package ca.ubc.cs317.dnslookup;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }


    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        String name = node.getHostName();
        String[] nameParts = name.split("\\.");
        ByteArrayOutputStream nameBytesOutputStream = new ByteArrayOutputStream();
        DataOutputStream nameDataOutputStream = new DataOutputStream(nameBytesOutputStream);

        // QUERY ID SECTION:
        int queryID = random.nextInt(65535);
        nameDataOutputStream.writeShort(queryID);

        // QR | OPCODE | AA section and response code sections:
        int queryCodes = 0;
//        nameDataOutputStream.writeShort(queryCodes); // UNCOMMENT THIS LINE
        // TODO: CHANGE THIS BACK BEFORE FINAL SUBMISSION
        nameDataOutputStream.writeByte(1); //REMOVE THIS LINE - REQUESTS RECURSION
        nameDataOutputStream.writeByte(0); //REMOVE THIS LINE

        // QDCOUNT - We only send 1 question with each query
        int queryCount = 1;
        nameDataOutputStream.writeShort(queryCount);

        // ANCOUNT - 0 for query
        int ansCount = 0;
        nameDataOutputStream.writeShort(ansCount);

        // NSCOUNT / name server records - 0 for query
        int nsCount = 0;
        nameDataOutputStream.writeShort(nsCount);

        // ARCOUNT / additional records - 0 for query
        int arCount = 0;
        nameDataOutputStream.writeShort(arCount);

        // QNAME:
        // Converts an ASCII domain like www.cs.ubc.ca to byte representation
        // source for byte writing: https://levelup.gitconnected.com/dns-request-and-response-in-java-acbd51ad3467
        for(int i = 0; i < nameParts.length; i++) {
            byte[] domainBytes = nameParts[i].getBytes(StandardCharsets.UTF_8);
            nameDataOutputStream.writeByte(domainBytes.length);
            nameDataOutputStream.write(domainBytes);
        }
        nameDataOutputStream.writeByte(0); // 00 byte to end the QNAME

        // QTYPE:
        int qType = node.getType().getCode();
        nameDataOutputStream.writeShort(qType);

        // QClass:
        int qClass = 1; // 1 for IN or Internet
        nameDataOutputStream.writeShort(qClass);

        message = nameBytesOutputStream.toByteArray();

        DatagramPacket udpPacketSend = new DatagramPacket(message, message.length, server, DEFAULT_DNS_PORT);
        socket.send(udpPacketSend);

        byte[] responseData = new byte[1024];
        DatagramPacket udpPacketReceive = new DatagramPacket(responseData, responseData.length, server, DEFAULT_DNS_PORT);

        // source: https://stackoverflow.com/questions/10556829/sending-and-receiving-udp-packets
        while (true) {
            try {
                socket.receive(udpPacketReceive);
                return new DNSServerResponse(ByteBuffer.wrap(udpPacketReceive.getData()), queryID);
            }
            catch (SocketTimeoutException e) {
                // Time out after 5 seconds
                // Send and receive again on first time out
                socket.send(udpPacketSend);
                while (true) {
                    try {
                        socket.receive(udpPacketReceive);
                        return new DNSServerResponse(ByteBuffer.wrap(udpPacketReceive.getData()), queryID);
                    }
                    catch (SocketTimeoutException e2) {
                        // On second time out, print the record with a -1
                        // TODO: Does this require return anything other than null here?
                        return null;
                    }
                }
            }
        }
    }

    public static String decodeName(ByteBuffer responseBuffer, int startBuffPos) throws IOException {

        //TODO: For testing only, remove this entire codeblock when done
        String temp = "www.cs.ubc.ca";
        String[] tempParts = temp.split("\\.");
        ByteArrayOutputStream nameBytesOutputStream = new ByteArrayOutputStream();
        DataOutputStream nameDataOutputStream = new DataOutputStream(nameBytesOutputStream);
        for(int i = 0; i < tempParts.length; i++) {
            byte[] domainBytes = tempParts[i].getBytes(StandardCharsets.UTF_8);
            nameDataOutputStream.writeByte(domainBytes.length);
            nameDataOutputStream.write(domainBytes);
        }
        nameDataOutputStream.writeByte(0); // 00 byte to end the QNAME
        responseBuffer = ByteBuffer.wrap(nameBytesOutputStream.toByteArray());
        // delete above

        // Function to get the name / cname
        byte[] buffer = responseBuffer.array();
        int pos = startBuffPos;
        List<String> nameParts = new ArrayList<String>();
        while (buffer[pos] != 0) {
            // if the first two bits of the byte is 11 then we have a pointer, if 00 then label
            if (((buffer[pos] >>> 6) & 3) == 3) {
                int offset = responseBuffer.getShort(pos) & 16383; // 16383 == 0011111111111111 in binary
                pos = offset;
            } else {
                int length = responseBuffer.get(pos) & 15; // 15 == 001111 in binary
                StringBuffer sb = new StringBuffer();
                for (int i = pos + 1; i < pos + length + 1 ; i++) {
                    sb.append((char) responseBuffer.get(i));
                }
                nameParts.add(sb.toString());
                pos += length + 1;
            }
        }
        String name = String.join(".", nameParts);
        return name;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        // TODO (PART 1): Implement this
        int serverTxID = responseBuffer.getShort(0);
        int flagBits = responseBuffer.get(2);
        boolean isResponse = ((flagBits >>> 7) & 1) != 0;
        boolean isAuthoritativeAns = ((flagBits >>> 3) & 1) != 0;
        int responseCode = responseBuffer.get(3) & 15; // 0 if no error,  1 - 5 means errors
        int ansCount = responseBuffer.getShort(6);
        int nsCount = responseBuffer.getShort(8);
        int arCount = responseBuffer.getShort(10);

        byte[] buffer = responseBuffer.array();
        int buffPos = 12;
        while (buffPos < buffer.length ) {
        // Check # of queries, get past them

        // Check # resources records
        // Based on Type, parse the bytes after the name differently then create the resource record


            try {
                // Check if decodeName needs to be used, 11 or 00
                // if 00 then run decodeName and advance the counter by length of the name + name.split(\\.).length() + 1
                // if 11 then run decodeName and advance the counter by 2
                String name = decodeName(responseBuffer, 0);

            } catch (IOException e) {
                //
            }
        }

        return null;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}


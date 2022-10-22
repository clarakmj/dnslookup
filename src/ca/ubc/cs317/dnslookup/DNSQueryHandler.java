package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
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


    // Converts an ASCII domain like www.cs.ubc.ca to HEX representation 03 77 77 77 02 63 73 03 75 62 63 02 63 61 00
    // source for String.format: https://stackoverflow.com/questions/18215336/what-does-b-0xff-mean
    public static String createEncodedQName(DNSNode node) throws IOException {
        // www.cs.ubc.ca
        // keep a global StringBuffer to concat the big parts
        // keep a local StringBuffer to create the 77 77 77
        // then a counter until . is  hit, append the counter to the global StringBuffer and contents of the local up until that point
        // then reset the counter and
        String name = node.getHostName();
        StringBuffer sbName = new StringBuffer();
        StringBuffer sbNameParts = new StringBuffer();
        int counter = 0;
        for(int i = 0; i <= name.length(); i++) {
            if (i == name.length()) {
                sbName.append(String.format("%02x", counter & 0xff) + " ");
                sbName.append(sbNameParts);
                continue;
            }
            Character c = name.charAt(i);
            if (c.equals('.')) {
                sbName.append(String.format("%02x", counter & 0xff) + " ");
                sbName.append(sbNameParts);
                sbNameParts.setLength(0);
                counter = 0;
                continue;
            }
            String hexString = String.format("%02x", c & 0xff);
            sbNameParts.append(hexString + " ");
            counter++;
        }
        sbName.append("00"); // 00 byte to end the QNAME
        String encodedQuestion = sbName.toString().trim();
        return encodedQuestion;
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
        // TODO (PART 1): Implement this
        System.out.println(DNSQueryHandler.createEncodedQName(node));
        return null;
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


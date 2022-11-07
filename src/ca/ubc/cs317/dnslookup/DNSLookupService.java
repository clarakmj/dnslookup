package ca.ubc.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

public class DNSLookupService {

    private static boolean p1Flag = false; // isolating part 1
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static DNSCache cache = DNSCache.getInstance();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length == 2 && args[1].equals("-p1")) {
            p1Flag = true;
        } else if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            DNSQueryHandler.openSocket();
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    boolean verboseTracing = false;
                    if (commandArgs[1].equalsIgnoreCase("on")) {
                        verboseTracing = true;
                        DNSQueryHandler.setVerboseTracing(true);
                    }
                    else if (commandArgs[1].equalsIgnoreCase("off")) {
                        DNSQueryHandler.setVerboseTracing(false);
                    }
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
            }

        } while (true);

        DNSQueryHandler.closeSocket();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the results for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (p1Flag) { // For isolating part 1 testing only
            retrieveResultsFromServer(node, rootServer);
            return Collections.emptySet();
        } else if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        // return cached results if query requested before
        Set<ResourceRecord> cachedRes = cache.getCachedResults(node);
        if (cachedRes.size() > 0) {
            return cachedRes;
        }
        // check CNAME
        cachedRes = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
        if (cachedRes.size() > 0) {
            for (ResourceRecord rr : cachedRes) {
                DNSNode node2 = new DNSNode(rr.getTextResult(), node.getType());
                Set<ResourceRecord> res = getResults(node2, (indirectionLevel+1));
//                for (ResourceRecord r : res) {
//                    ResourceRecord newRecord = new ResourceRecord(node.getHostName(), node.getType(), r.getTTL(), r.getInetResult());
//                    cache.addResult(newRecord);
//                }
                // TODO: Check other CNAMES if results for that CNAME is empty before returning
                if (!res.isEmpty()) {
                    return res;
                }
            }
        }

        // retrieve results from server and return cached results if exists
        retrieveResultsFromServer(node, rootServer);
        cachedRes = cache.getCachedResults(node);
        if (cachedRes.size() > 0) {
            return cachedRes;
        }

        // check CNAME
        Set<ResourceRecord> records = cache.getCachedResults(new DNSNode(node.getHostName(), RecordType.CNAME));
        if (records.size() > 0) {
            for (ResourceRecord r1 : records) {
                DNSNode node3 = new DNSNode(r1.getTextResult(), node.getType());
                Set<ResourceRecord> res = getResults(node3, (indirectionLevel+1));
                if (!res.isEmpty()) {
                    return res;
                }
            }
        }

        // nothing came back so return empty set
        return Collections.emptySet();
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] message = new byte[512]; // query is no longer than 512 bytes

        try {
            DNSServerResponse serverResponse = DNSQueryHandler.buildAndSendQuery(message, server, node);

            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(serverResponse.getTransactionID(),
                    serverResponse.getResponse(),
                    cache);
            if (nameservers == null) nameservers = Collections.emptySet();

            if (p1Flag) return; // For testing part 1 only

            queryNextLevel(node, nameservers);

        } catch (IOException | NullPointerException ignored){}
    }

    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param nameservers List of name servers returned from the previous level to query the next level.
     */
    private static void queryNextLevel(DNSNode node, Set<ResourceRecord> nameservers) {
        // Base case: Check if the actual node we want is already in the cache, if so then just return
        Set<ResourceRecord> cachedRes = cache.getCachedResults(node);
        if (!cachedRes.isEmpty()) {
            return;
        }

        // Return if cname base case
        if (cachedRes.iterator().hasNext()) {
            cachedRes.iterator().next().getType().equals(RecordType.CNAME);
            return;
        }

        // We don't have the actual node so we need to check the Authority section for the next level
        for (ResourceRecord record : nameservers) {
            DNSNode newNode = new DNSNode(record.getTextResult(), RecordType.A);
            Set<ResourceRecord> results = cache.getCachedResults(newNode);
            if (!results.isEmpty()) {
            // Cache has results, either bc we queried before or it was in the additional records
                for (ResourceRecord result : results) {
                    retrieveResultsFromServer(node, result.getInetResult());
                    // Check if we got an answer at that level
                    if (!cache.getCachedResults(node).isEmpty()) {
                        return;
                    }
                    // Check if CNAME was received at that level
                    DNSNode cNameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
                    if (!cache.getCachedResults(cNameNode).isEmpty()) {
                        return;
                    }

                }
//                return;
            } else {
            // Make a call to the root server with the NS record text result name
                retrieveResultsFromServer(newNode, rootServer);
            // Retrieve the newNode from the cache and retrieveResultsFromServer to it using the original node and newNode ip address
                Set<ResourceRecord> middleDNSRecordResults = cache.getCachedResults(newNode);
                for (ResourceRecord result : middleDNSRecordResults) {
                    retrieveResultsFromServer(node, result.getInetResult());
                    // Check if we got an answer at that level
                    if (!cache.getCachedResults(node).isEmpty()) {
                        return;
                    }
                    // Check if CNAME was received at that level
                    DNSNode cNameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
                    if (!cache.getCachedResults(cNameNode).isEmpty()) {
                        return;
                    }
                }
            }
        }

    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}

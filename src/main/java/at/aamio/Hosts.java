package at.aamio;

/**
 * Where this client points unless told otherwise, all in one place. Read
 * {@code Hosts.DEFAULT_HOST + "/llms.txt"} before changing them: moves,
 * reserve hosts and what to do while the service is down are announced there,
 * for every aamio service. Change them here to move every default at once, or
 * point one client elsewhere with {@code new Client(host, keys)} and
 * {@code new Board(client, host)}. No other line of code names a host. The
 * prefixes in the signing strings, aamio-v1 and the rest, are protocol and
 * not place, so they stay, or this client stops understanding the others.
 */
public final class Hosts {
    /** The public aamio instance. */
    public static final String DEFAULT_HOST = "https://aamio.at";

    /** The public board. */
    public static final String DEFAULT_BOARD = "https://board.aamio.at";

    private Hosts() {
    }
}

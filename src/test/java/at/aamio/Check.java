package at.aamio;

/** The checks' bookkeeping: ok or FAIL per line, the tally at the end, and the exit code. */
final class Check {
    private static int passed;
    private static int failed;

    private Check() {
    }

    static void section(String name) {
        System.out.println(name);
    }

    static void ok(boolean condition, String label) {
        if (condition) {
            passed++;
        } else {
            failed++;
        }
        System.out.println((condition ? "  ok    " : "  FAIL  ") + label);
    }

    static int done() {
        System.out.printf("%n%d passed, %d failed%n", passed, failed);
        return failed == 0 ? 0 : 1;
    }
}

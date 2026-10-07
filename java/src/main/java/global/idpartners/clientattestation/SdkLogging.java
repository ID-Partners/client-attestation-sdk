/*
 * Logging for the SDK, through java.lang.System.Logger (no logging dependency). Off unless the caller
 * passes a logger: see ClientAttestation.Builder#logger. Event names and attribute keys are shared with
 * the other ports; docs/logging.md is the contract.
 */
package global.idpartners.clientattestation;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ResourceBundle;

/**
 * The SDK's logging hook. Pass {@code System.getLogger(SdkLogging.LOGGER_NAME)} (or any
 * {@link System.Logger}) to {@link ClientAttestation.Builder#logger(System.Logger)} to see what the SDK
 * does; by default nothing is logged.
 *
 * <p>Each record's message is {@code event key=value ...}, for example
 * {@code token.obtained host=pf.example.com token_type=DPoP expires_in=3600}. Tokens, attestations, proofs,
 * SVIDs, challenge values, key material and credential header values are never logged; URLs appear only
 * as {@code host} and {@code path}.
 */
public final class SdkLogging {

    /** The logger name to pass to {@link System#getLogger(String)}. */
    public static final String LOGGER_NAME = "global.idpartners.clientattestation";

    /** A logger that drops everything: the default, so the SDK is silent until configured. */
    static final System.Logger NOOP = new NoopLogger();

    private final System.Logger logger;

    SdkLogging(System.Logger logger) {
        this.logger = logger != null ? logger : NOOP;
    }

    void debug(String event, Object... attrs) {
        log(System.Logger.Level.DEBUG, event, attrs);
    }

    void info(String event, Object... attrs) {
        log(System.Logger.Level.INFO, event, attrs);
    }

    void warn(String event, Object... attrs) {
        log(System.Logger.Level.WARNING, event, attrs);
    }

    /** Emits {@code event} with alternating key/value {@code attrs}; null values are left out. */
    void log(System.Logger.Level level, String event, Object... attrs) {
        if (!this.logger.isLoggable(level)) {
            return;
        }
        this.logger.log(level, format(event, attrs));
    }

    static String format(String event, Object... attrs) {
        StringBuilder out = new StringBuilder(event);
        for (int i = 0; i + 1 < attrs.length; i += 2) {
            Object value = attrs[i + 1];
            if (value == null) {
                continue;
            }
            out.append(' ').append(attrs[i]).append('=').append(render(value));
        }
        return out.toString();
    }

    private static String render(Object value) {
        String s = guard(String.valueOf(value));
        if (s.isEmpty() || s.chars().anyMatch(c -> c == ' ' || c == '"' || c == '=' || c < 0x20)) {
            return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")
                    + '"';
        }
        return s;
    }

    /** Backstop: a value that looks like a JWT is replaced, whatever key it was logged under. */
    static String guard(String s) {
        if (s.contains("eyJ")) {
            return "<redacted:" + s.getBytes(StandardCharsets.UTF_8).length + " bytes>";
        }
        return s;
    }

    /** Host (and port, when one is given) of {@code url}, or null. */
    static String host(String url) {
        try {
            URI uri = URI.create(url.strip());
            if (uri.getHost() == null) {
                return null;
            }
            return uri.getPort() >= 0 ? uri.getHost() + ":" + uri.getPort() : uri.getHost();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Path of {@code url} with no query or fragment, or null. */
    static String path(String url) {
        try {
            String p = URI.create(url.strip()).getRawPath();
            return p == null || p.isEmpty() ? "/" : p;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static final class NoopLogger implements System.Logger {
        @Override
        public String getName() {
            return LOGGER_NAME;
        }

        @Override
        public boolean isLoggable(Level level) {
            return false;
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            // silent by default
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            // silent by default
        }
    }
}

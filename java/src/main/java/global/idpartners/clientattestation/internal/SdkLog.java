/*
 * Logging for the SDK, through java.lang.System.Logger (no logging dependency). Off unless the caller
 * passes a logger: see ClientAttestation.Builder#logger. Event names and attribute keys are shared with
 * the other ports; docs/logging.md is the contract.
 */
package global.idpartners.clientattestation.internal;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ResourceBundle;

/**
 * The SDK's logging plumbing: formats {@code event key=value ...} records, refuses anything that looks
 * like a JWT, and logs URLs only as host and path. Callers pass a {@link System.Logger} to
 * {@code ClientAttestation.Builder#logger} or {@code AccessTokenValidator.Builder#logger}.
 *
 * <p><b>Not API.</b> This package is internal: it is public only so the SDK's own packages can share it,
 * it is not exported by the module, and it may change in any release.
 */
public final class SdkLog {

    /** The SDK's logger name (also {@code ClientAttestation.LOGGER_NAME}). */
    public static final String LOGGER_NAME = "global.idpartners.clientattestation";

    /** A logger that drops everything: the default, so the SDK is silent until configured. */
    public static final System.Logger NOOP = new NoopLogger();

    private final System.Logger logger;

    public SdkLog(System.Logger logger) {
        this.logger = logger != null ? logger : NOOP;
    }

    public void debug(String event, Object... attrs) {
        log(System.Logger.Level.DEBUG, event, attrs);
    }

    public void info(String event, Object... attrs) {
        log(System.Logger.Level.INFO, event, attrs);
    }

    public void warn(String event, Object... attrs) {
        log(System.Logger.Level.WARNING, event, attrs);
    }

    /** Emits {@code event} with alternating key/value {@code attrs}; null values are left out. */
    public void log(System.Logger.Level level, String event, Object... attrs) {
        if (!this.logger.isLoggable(level)) {
            return;
        }
        this.logger.log(level, format(event, attrs));
    }

    /**
     * The message for {@code event}: {@code event key=value ...} from alternating key/value {@code attrs},
     * leaving out null values, quoting values that need it and redacting anything that looks like a JWT.
     * Shared with the {@code tokenvalidator} package.
     *
     * @param event the event name
     * @param attrs alternating keys and values
     * @return the message
     */
    public static String format(String event, Object... attrs) {
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
    public static String guard(String s) {
        if (s.contains("eyJ")) {
            return "<redacted:" + s.getBytes(StandardCharsets.UTF_8).length + " bytes>";
        }
        return s;
    }

    /**
     * Host (and port, when one is given) of {@code url}, or null.
     *
     * @param url the URL
     * @return its host, or null
     */
    public static String host(String url) {
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

    /**
     * Path of {@code url} with no query or fragment, or null.
     *
     * @param url the URL
     * @return its path, or null
     */
    public static String path(String url) {
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

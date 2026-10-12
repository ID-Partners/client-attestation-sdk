/*
 * Logging for the SDK, through java.lang.System.Logger (no logging dependency). Off unless the caller
 * passes a logger: see ClientAttestation.Builder#logger. Event names and attribute keys are shared with
 * the other ports; docs/logging.md is the contract.
 */
package global.idpartners.clientattestation.internal;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The SDK's logging plumbing: formats {@code event key=value ...} records, refuses anything that looks
 * like a credential, and logs URLs only as host and path. Callers pass a {@link System.Logger} to
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

    // The backstop (docs/logging.md, the same rule in every port): an attribute is redacted when its key
    // names a credential, or its value carries one this SDK handles. Keys are matched in lower case.
    private static final Set<String> SECRET_KEYS = Set.of(
            "svid", "proof", "assertion", "client_assertion", "subject_token", "actor_token", "client_secret",
            "attestation", "access_token", "refresh_token", "id_token", "authorization", "dpop",
            "oauth-client-attestation", "oauth-client-attestation-pop", "auth_req_id", "code", "handle",
            "token", "secret", "password", "private_key", "vault_token", "x-vault-token");
    private static final List<String> SECRET_KEY_SUFFIXES =
            List.of("_token", "-token", "_secret", "-secret", "_password");
    // Vault/OpenBao tokens: hvs./hvb./hvr. and the older s./b./r. forms, standing alone.
    private static final Pattern VAULT_TOKEN = Pattern.compile("(?:^|[^A-Za-z0-9._-])"
            + "(?:hv[sbr]\\.[A-Za-z0-9_-]{20,}|[sbr]\\.[A-Za-z0-9_-]{24,}(?:$|[^A-Za-z0-9._-]))");
    // An Authorization header value anywhere in the string: a scheme this SDK sends, standing alone, then
    // whitespace and the first character of a credential ("Bearer x", " Bearer x", "Authorization: Bearer x").
    // A bare scheme name ("Bearer", "token_type=Bearer", "dpop_combined") is not one.
    private static final Pattern AUTH_SCHEME = Pattern.compile(
            "(?:^|[^A-Za-z0-9_-])(?:bearer|dpop|basic)[ \\t]+[A-Za-z0-9._~+/-]", Pattern.CASE_INSENSITIVE);

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
     * leaving out null values, quoting values that need it, and redacting values under a credential key
     * ({@link #secretKey}) and anything that looks like a credential ({@link #guard}).
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
            String key = text(attrs[i]);
            out.append(' ').append(key).append('=')
                    .append(render(secretKey(key) ? redacted(text(value)) : value));
        }
        return out.toString();
    }

    /** {@code String.valueOf}, except that a {@code toString} that throws never throws out of logging. */
    private static String text(Object value) {
        try {
            return String.valueOf(value);
        } catch (RuntimeException e) {
            return "<redacted>";
        }
    }

    private static String render(Object value) {
        String s = guard(text(value));
        if (s.isEmpty() || s.chars().anyMatch(c -> c == ' ' || c == '"' || c == '=' || c < 0x20)) {
            return '"' + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r")
                    + '"';
        }
        return s;
    }

    /**
     * Backstop: a value that looks like a credential is replaced, whatever key it was logged under. That is
     * a JWT (contains {@code eyJ}), a Vault/OpenBao token, or an {@code Authorization} header value.
     *
     * @param s the value
     * @return {@code s}, or its redacted form
     */
    public static String guard(String s) {
        if (s.contains("eyJ") || VAULT_TOKEN.matcher(s).find() || AUTH_SCHEME.matcher(s).find()) {
            return redacted(s);
        }
        return s;
    }

    /**
     * Backstop: whether an attribute key names a credential, so its value is replaced whatever it looks
     * like (an opaque token, an {@code auth_req_id}, a ceremony handle).
     *
     * @param key the attribute key
     * @return true when its value is redacted
     */
    public static boolean secretKey(String key) {
        String k = key.toLowerCase(Locale.ROOT);
        return SECRET_KEYS.contains(k) || SECRET_KEY_SUFFIXES.stream().anyMatch(k::endsWith);
    }

    /**
     * The printed form of a secret in a {@code toString}: {@code <redacted:N bytes>}, or {@code null}.
     *
     * @param s the secret, or null
     * @return its redacted form
     */
    public static String redacted(String s) {
        return s == null ? "null" : "<redacted:" + s.getBytes(StandardCharsets.UTF_8).length + " bytes>";
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

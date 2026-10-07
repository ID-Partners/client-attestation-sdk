package global.idpartners.clientattestation.tokenvalidator;

import global.idpartners.clientattestation.internal.SdkLog;

/**
 * The validator's logging hook: the caller's {@link System.Logger}, or nothing. Messages are
 * {@code event key=value ...} in the same format as the rest of the SDK (docs/logging.md). Tokens, client
 * secrets and key material are never passed in.
 */
final class ValidatorLog {

    private final System.Logger logger;

    ValidatorLog(System.Logger logger) {
        this.logger = logger;
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

    private void log(System.Logger.Level level, String event, Object... attrs) {
        if (this.logger == null || !this.logger.isLoggable(level)) {
            return;
        }
        this.logger.log(level, SdkLog.format(event, attrs));
    }
}

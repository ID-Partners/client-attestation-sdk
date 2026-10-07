package global.idpartners.clientattestation;

import java.util.Map;

/**
 * How an {@link AttesterProfile} talks to the attester. The client supplies it, so every call shares the
 * client's timeout, redirect and size limits, https rule and logging ({@code http.failed}).
 */
@FunctionalInterface
public interface AttesterTransport {

    /**
     * Sends {@code body} (as JSON, if non-null) and returns the JSON object response.
     *
     * @param step   names the call in logs ({@code discover}, {@code mint})
     * @param method the HTTP method
     * @param url    the URL
     * @param body   the JSON request body, or {@code null} for none
     * @return the JSON object response (empty for an empty 2xx body)
     * @throws Exception on a non-2xx status, a transport failure, or a body that is not a JSON object
     */
    Map<String, Object> requestJson(String step, String method, String url, Map<String, Object> body)
            throws Exception;
}

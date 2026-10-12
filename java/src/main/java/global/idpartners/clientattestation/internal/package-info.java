/**
 * <b>Not API.</b> Plumbing shared by the SDK's own packages: the one outbound HTTP path
 * ({@link global.idpartners.clientattestation.internal.HttpTransport}), the logging helper
 * ({@link global.idpartners.clientattestation.internal.SdkLog}) and the strict JSON reader
 * ({@link global.idpartners.clientattestation.internal.StrictJson}).
 *
 * <p>The types here are public only because Java has no other way to share them between packages. The
 * module does not export this package, it is left out of the published API snapshot, and anything in it
 * may change or disappear in any release. Do not import it.
 */
package global.idpartners.clientattestation.internal;

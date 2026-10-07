/**
 * Auto-detect the workload's platform identity (the evidence it presents to the attester).
 *
 * The workload proves *what it is* with a token its runtime already issues. Which token, and where it
 * comes from, depends on the runtime:
 *
 * - an explicit token in an environment variable (any runtime that injects one),
 * - a projected/mounted token file (Kubernetes, GKE),
 * - a SPIRE Workload API socket (SPIRE / SPIFFE),
 * - the GCP metadata server (GCE, GKE, Cloud Run, Vertex AI Agent Engine).
 *
 * {@link autoDetectEvidence} tries these in order and returns the first that applies, so a developer
 * can write `new ClientAttestation(pfHost)` and have it work without naming the source. Override by
 * passing an explicit {@link SvidSource} to {@link ClientAttestation}.
 */
import { TransportError } from "./errors.js";
import { request, snippet } from "./http.js";
import { envVar, importNodeBuiltin } from "./runtime.js";
import { SpireWorkloadApiSvidSource, StaticSvidSource, type SvidSource } from "./svid-source.js";

/** Environment variable holding the evidence token itself (static). */
export const ENV_SVID = "CLIENT_ATTESTATION_SVID";
/** Environment variable holding a path to a projected token file. */
export const ENV_TOKEN_FILE = "CLIENT_ATTESTATION_TOKEN_FILE";
/** SPIRE Workload API socket (standard SPIFFE var). */
export const ENV_SPIFFE_SOCKET = "SPIFFE_ENDPOINT_SOCKET";

/** Default projected-token path used by the Kubernetes/GKE serviceAccountToken volume convention. */
export const DEFAULT_TOKEN_FILE = "/var/run/secrets/tokens/attester-token";
/** Default SPIRE agent socket path. */
export const DEFAULT_SPIFFE_SOCKET = "/tmp/spire-agent/public/api.sock";
/** GCP metadata server origin. */
export const GCP_METADATA_BASE = "http://metadata.google.internal";
/** GCP metadata server identity endpoint (returns a Google-signed ID token for the runtime SA). */
export const GCP_METADATA_IDENTITY =
  GCP_METADATA_BASE + "/computeMetadata/v1/instance/service-accounts/default/identity";

/** No platform identity could be detected and none was supplied. */
export class EvidenceNotFound extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceNotFound";
  }
}

/**
 * Reads the evidence token from a file on every fetch.
 *
 * Kubernetes and GKE mount a short-lived, auto-rotated service-account token into the pod as a file
 * (a projected `serviceAccountToken` volume). Reading it fresh each time picks up the rotation. The
 * file's audience must already be the attester's evidence audience — set it when you declare the volume.
 *
 * Needs a filesystem: `node:fs/promises` is loaded on the first `fetch`, which throws a
 * `ClientAttestationError` on a runtime without it.
 */
export class FileTokenSvidSource implements SvidSource {
  constructor(private readonly path: string) {}

  async fetch(_audience: string): Promise<string> {
    const { readFile } = await importNodeBuiltin<typeof import("node:fs/promises")>(
      "fs/promises",
      "FileTokenSvidSource",
    );
    const contents = await readFile(this.path, "utf8");
    return contents.trim();
  }
}

/**
 * Fetches a Google-signed ID token for the runtime service account from the GCP metadata server.
 *
 * Works on any Google runtime that exposes the metadata server (GCE, GKE, Cloud Run, Vertex AI Agent
 * Engine). The token's `aud` is the attester's evidence audience; `sub` is the service account. No
 * google-auth dependency — a plain metadata call.
 */
export class GoogleMetadataSvidSource implements SvidSource {
  /**
   * @param timeoutMs per-request timeout.
   * @param identityUrl the identity endpoint; internal, for tests - defaults to the real metadata server.
   */
  constructor(
    private readonly timeoutMs = 5000,
    private readonly identityUrl = GCP_METADATA_IDENTITY,
  ) {}

  async fetch(audience: string): Promise<string> {
    const url = `${this.identityUrl}?audience=${encodeURIComponent(audience)}&format=full`;
    const res = await request(url, {
      method: "GET",
      headers: { "Metadata-Flavor": "Google" },
      timeoutMs: this.timeoutMs,
    });
    if (!res.ok) {
      throw new TransportError(`GCP metadata identity endpoint -> ${res.status}`, "status", {
        status: res.status,
        body: snippet(res.body),
      });
    }
    return res.body.trim();
  }
}

/**
 * A path-existence check, or one that always answers `false` on a runtime with no filesystem (an edge
 * runtime), where the file and socket sources cannot apply.
 */
async function pathProbe(): Promise<(path: string) => boolean> {
  try {
    const { existsSync } = await importNodeBuiltin<typeof import("node:fs")>("fs", "autoDetectEvidence");
    return existsSync;
  } catch {
    return () => false;
  }
}

async function gcpMetadataAvailable(base: string, timeoutMs = 300): Promise<boolean> {
  try {
    const res = await request(base + "/computeMetadata/v1/", {
      method: "GET",
      headers: { "Metadata-Flavor": "Google" },
      timeoutMs,
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Internal overrides for {@link autoDetectEvidence}, so tests can point detection at fixtures instead
 * of the host's real paths and the real GCP metadata server. Not part of the supported API.
 *
 * @internal
 */
export interface AutoDetectOptions {
  /** Path probed in place of {@link DEFAULT_TOKEN_FILE}. */
  defaultTokenFile?: string;
  /** Path probed in place of {@link DEFAULT_SPIFFE_SOCKET}. */
  defaultSpiffeSocket?: string;
  /** Origin used in place of {@link GCP_METADATA_BASE} for the probe and the identity call. */
  gcpMetadataBase?: string;
}

/**
 * Return the first evidence source that applies to this runtime, or throw with guidance.
 *
 * Order: explicit env token, projected token file, SPIRE socket, GCP metadata server. A source named
 * by an environment variable ({@link ENV_TOKEN_FILE}, {@link ENV_SPIFFE_SOCKET}) whose path does not
 * exist throws {@link EvidenceNotFound} naming the variable; it never falls through to the next source.
 */
export async function autoDetectEvidence(opts: AutoDetectOptions = {}): Promise<SvidSource> {
  const exists = await pathProbe();
  const defaultTokenFile = opts.defaultTokenFile ?? DEFAULT_TOKEN_FILE;
  const defaultSocket = opts.defaultSpiffeSocket ?? DEFAULT_SPIFFE_SOCKET;
  const metadataBase = (opts.gcpMetadataBase ?? GCP_METADATA_BASE).replace(/\/+$/, "");

  const staticToken = envVar(ENV_SVID);
  if (staticToken) {
    return new StaticSvidSource(staticToken.trim());
  }

  // An explicitly configured source that is missing is a misconfiguration: fail closed rather than
  // fall through to a different identity the operator did not choose.
  const tokenFile = envVar(ENV_TOKEN_FILE);
  if (tokenFile) {
    if (!exists(tokenFile)) {
      throw new EvidenceNotFound(`${ENV_TOKEN_FILE} is set to ${tokenFile}, but no such file exists`);
    }
    return new FileTokenSvidSource(tokenFile);
  }
  if (exists(defaultTokenFile)) {
    return new FileTokenSvidSource(defaultTokenFile);
  }

  const socket = envVar(ENV_SPIFFE_SOCKET);
  if (socket) {
    const socketPath = socket.replace(/^unix:\/\//, "");
    if (!exists(socketPath)) {
      throw new EvidenceNotFound(`${ENV_SPIFFE_SOCKET} is set to ${socket}, but no such socket exists`);
    }
    return new SpireWorkloadApiSvidSource(socketPath);
  }
  if (exists(defaultSocket)) {
    return new SpireWorkloadApiSvidSource(defaultSocket);
  }

  if (await gcpMetadataAvailable(metadataBase)) {
    return new GoogleMetadataSvidSource(
      5000,
      metadataBase + "/computeMetadata/v1/instance/service-accounts/default/identity",
    );
  }

  throw new EvidenceNotFound(
    "Could not auto-detect the workload's platform identity. Set one of " +
      `${ENV_SVID} (the token), ${ENV_TOKEN_FILE} (a token file), or ${ENV_SPIFFE_SOCKET} (SPIRE socket), ` +
      "or pass evidence=<SvidSource> to ClientAttestation explicitly.",
  );
}

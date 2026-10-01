/**
 * OAuth 2.0/2.1 protected-resource conventions on top of {@link AccessTokenValidator}.
 *
 * A {@link ProtectedResource} is the resource-server side of any OAuth-protected HTTP service — an MCP
 * server (OAuth 2.1 resource server per the MCP authorization spec), an A2A agent, or a plain REST API. It
 * adds what the validator itself doesn't: RFC 9728 Protected Resource Metadata
 * (`/.well-known/oauth-protected-resource`), RFC 6750 bearer extraction + `WWW-Authenticate` challenges, and
 * a request guard that binds the token audience to this resource (RFC 8707). Protocol-neutral — not MCP-only.
 */
import * as errors from "./errors.js";
import type { ValidationError } from "./errors.js";
import type { ValidationResult } from "./result.js";
import type { AccessTokenValidator } from "./validator.js";

const WELL_KNOWN = "/.well-known/oauth-protected-resource";

/** Extract the token from an `Authorization: Bearer <token>` header value, or null. */
export function bearerToken(authorizationHeader?: string | null): string | null {
  if (!authorizationHeader) return null;
  const match = /^\s*Bearer\s+(.+?)\s*$/i.exec(authorizationHeader);
  return match ? match[1] : null;
}

/** RFC 9728 protected-resource metadata document. */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
  scopes_supported?: string[];
}

/** The outcome of guarding a request. */
export interface AuthDecision {
  authorized: boolean;
  result?: ValidationResult;
  status: number;
  wwwAuthenticate?: string;
  error?: string;
  errorDescription?: string | null;
}

/**
 * An OAuth-protected resource server. The `validator` must accept `resource` as an audience — that binds
 * incoming tokens to this resource (RFC 8707), which MCP servers MUST enforce. The constructor refuses one
 * that doesn't.
 */
export class ProtectedResource {
  readonly resource: string;
  readonly authorizationServers: string[];
  readonly scopesSupported: string[];
  readonly #validator: AccessTokenValidator;

  constructor(
    resource: string,
    authorizationServers: string[],
    validator: AccessTokenValidator,
    scopesSupported: string[] = [],
  ) {
    if (!validator.config.audiences.includes(resource)) {
      throw new Error(`the validator does not accept this resource (${resource}) as an audience`);
    }
    this.resource = resource;
    this.authorizationServers = authorizationServers;
    this.#validator = validator;
    this.scopesSupported = scopesSupported;
  }

  metadata(): ProtectedResourceMetadata {
    const md: ProtectedResourceMetadata = {
      resource: this.resource,
      authorization_servers: this.authorizationServers,
      bearer_methods_supported: ["header"],
    };
    if (this.scopesSupported.length > 0) md.scopes_supported = this.scopesSupported;
    return md;
  }

  metadataPath(): string {
    const path = new URL(this.resource).pathname;
    return path && path !== "/" ? WELL_KNOWN + path : WELL_KNOWN;
  }

  metadataUrl(): string {
    const u = new URL(this.resource);
    return `${u.protocol}//${u.host}${this.metadataPath()}`;
  }

  challenge(error?: string, errorDescription?: string | null): string {
    const params: string[] = [];
    if (error) {
      params.push(`error="${quote(error)}"`);
      if (errorDescription) params.push(`error_description="${quote(errorDescription)}"`);
    }
    params.push(`resource_metadata="${quote(this.metadataUrl())}"`);
    return "Bearer " + params.join(", ");
  }

  async authenticate(authorizationHeader?: string | null, requiredScopes?: string[]): Promise<AuthDecision> {
    const token = bearerToken(authorizationHeader);
    if (token == null) {
      return { authorized: false, status: 401, wwwAuthenticate: this.challenge(), errorDescription: "authentication required" };
    }
    const result = await this.#validator.validate(token, requiredScopes);
    if (result.valid) {
      return { authorized: true, result, status: 200 };
    }
    const [status, oauthError] = httpError(result.error);
    return {
      authorized: false,
      result,
      status,
      error: oauthError,
      errorDescription: result.errorDescription,
      wwwAuthenticate: this.challenge(oauthError, result.errorDescription),
    };
  }
}

function httpError(error: ValidationError | null): [number, string] {
  return error === errors.INSUFFICIENT_SCOPE ? [403, "insufficient_scope"] : [401, "invalid_token"];
}

/**
 * Make a value safe inside a quoted-string header parameter: drop CR, LF and every other control
 * character (0x00-0x1F, 0x7F) so nothing can split or forge a header, then escape backslash and quote.
 */
export function quote(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\x00-\x1f\x7f]/g, "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

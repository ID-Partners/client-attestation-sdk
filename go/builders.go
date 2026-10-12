package clientattestation

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// JWT "typ" header values for the three artifact kinds.
const (
	AttestationTyp = "oauth-client-attestation+jwt"
	PopTyp         = "oauth-client-attestation-pop+jwt"
	DpopTyp        = "dpop+jwt"
)

// ClientAttestationBuilder builds a Client Attestation JWT — the credential a
// Client Attester issues to name a client (sub = client_id) and bind its
// instance key via the RFC 7800 cnf.jwk claim. This is the attester side: sign
// with the attester's issuing key.
type ClientAttestationBuilder struct {
	attesterKey          *SigningKeyPair
	attesterSigner       JwsSigner
	issuer               string
	clientID             string
	cnfJWK               map[string]any
	issuedAt             *int64
	expiresAt            *int64
	ttl                  *int64
	authorizationDetails []map[string]any
	workload             map[string]any
	operatorSub          string
	operatorIss          string
	hasOperator          bool
}

// NewClientAttestationBuilder starts a builder signing with attesterKey and
// asserting the given issuer (attestation "iss").
func NewClientAttestationBuilder(attesterKey *SigningKeyPair, issuer string) *ClientAttestationBuilder {
	return &ClientAttestationBuilder{attesterKey: attesterKey, issuer: issuer}
}

// NewClientAttestationBuilderWithSigner starts a builder signing the attestation with an external
// JwsSigner (e.g. an *OpenBaoTransitSigner whose key lives in a vault) instead of a local SigningKeyPair.
func NewClientAttestationBuilderWithSigner(signer JwsSigner, issuer string) *ClientAttestationBuilder {
	return &ClientAttestationBuilder{attesterSigner: signer, issuer: issuer}
}

// ClientID sets the client being attested — the attestation "sub" (= client_id).
func (b *ClientAttestationBuilder) ClientID(clientID string) *ClientAttestationBuilder {
	b.clientID = clientID
	return b
}

// ConfirmationJWK binds a public instance JWK as cnf.jwk. It must be an EC (crv P-256, P-384 or P-521,
// x, y) or RSA (n, e) public key; Build refuses one carrying private or secret members (d, p, q, dp, dq,
// qi, oth, k) or another kty. Only those members and an optional "kid" are copied into the attestation.
func (b *ClientAttestationBuilder) ConfirmationJWK(publicInstanceJWK map[string]any) *ClientAttestationBuilder {
	b.cnfJWK = publicInstanceJWK
	return b
}

// ConfirmationKey binds the public half of the given instance key as cnf.jwk.
func (b *ClientAttestationBuilder) ConfirmationKey(instanceKey *SigningKeyPair) *ClientAttestationBuilder {
	return b.ConfirmationJWK(instanceKey.PublicJWK())
}

// IssuedAt sets an explicit "iat" (epoch seconds).
func (b *ClientAttestationBuilder) IssuedAt(epochSeconds int64) *ClientAttestationBuilder {
	b.issuedAt = &epochSeconds
	return b
}

// ExpiresAt sets an absolute "exp" (epoch seconds).
func (b *ClientAttestationBuilder) ExpiresAt(epochSeconds int64) *ClientAttestationBuilder {
	b.expiresAt = &epochSeconds
	return b
}

// ExpiresIn sets "exp" to iat + seconds.
func (b *ClientAttestationBuilder) ExpiresIn(seconds int64) *ClientAttestationBuilder {
	b.ttl = &seconds
	return b
}

// AuthorizationDetails sets the optional RFC 9396 authorization_details array.
func (b *ClientAttestationBuilder) AuthorizationDetails(details []map[string]any) *ClientAttestationBuilder {
	b.authorizationDetails = details
	return b
}

// Workload sets the optional attester-asserted workload object.
func (b *ClientAttestationBuilder) Workload(workload map[string]any) *ClientAttestationBuilder {
	b.workload = workload
	return b
}

// Operator names the client's OPERATOR — the human or organisation accountable for running this
// client, as distinct from the client itself ("sub") and from the principal it acts for.
//
// Deliberately a top-level claim rather than a member of Workload: workload describes the running
// software, whereas the operator is an accountability statement about who answers for it. It is
// per-client and static, so it does not affect how far an attestation can be cached.
//
// The shape mirrors RFC 8693 may_act ({"sub": ..., "iss": ...}) on purpose. An AS that wants the
// operator to become the party authorised to act for the subject can lift this straight into
// may_act; issuer names the OP the operator's sub is meaningful in, so the identifier is not
// ambiguous across directories. Pass "" for issuer to omit it.
//
// This is an ASSERTION by the attester, not proof the operator authorised anything. A relying AS
// should treat it as it treats the rest of the attestation: trusted exactly as far as the attester
// is.
func (b *ClientAttestationBuilder) Operator(sub string, issuer string) *ClientAttestationBuilder {
	b.operatorSub, b.operatorIss, b.hasOperator = sub, issuer, true
	return b
}

// Build signs and returns the compact attestation JWT.
func (b *ClientAttestationBuilder) Build() (string, error) {
	issuer, err := requireText(b.issuer, "issuer")
	if err != nil {
		return "", err
	}
	sub, err := requireText(b.clientID, "client_id")
	if err != nil {
		return "", err
	}
	if b.cnfJWK == nil {
		return "", fmt.Errorf("confirmation key (cnf.jwk) is required")
	}
	cnfJWK, err := confirmationJWK(b.cnfJWK)
	if err != nil {
		return "", err
	}
	iat := b.resolveIssuedAt()
	exp, err := b.resolveExpiry(iat)
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss": issuer,
		"sub": sub,
		"iat": iat,
		"exp": exp,
		"cnf": map[string]any{"jwk": cnfJWK},
	}
	if len(b.authorizationDetails) > 0 {
		claims["authorization_details"] = b.authorizationDetails
	}
	if len(b.workload) > 0 {
		claims["workload"] = b.workload
	}
	if b.hasOperator {
		sub, err := requireText(b.operatorSub, "operator sub")
		if err != nil {
			return "", err
		}
		op := map[string]any{"sub": sub}
		if b.operatorIss != "" {
			op["iss"] = b.operatorIss
		}
		claims["operator"] = op
	}
	if b.attesterSigner != nil {
		return signExternal(claims, b.attesterSigner, AttestationTyp)
	}
	return b.attesterKey.signCompact(claims, AttestationTyp, false)
}

func (b *ClientAttestationBuilder) resolveIssuedAt() int64 {
	if b.issuedAt != nil {
		return *b.issuedAt
	}
	return time.Now().Unix()
}

func (b *ClientAttestationBuilder) resolveExpiry(iat int64) (int64, error) {
	var exp int64
	switch {
	case b.expiresAt != nil:
		exp = *b.expiresAt
	case b.ttl != nil:
		exp = iat + *b.ttl
	default:
		return 0, fmt.Errorf("expiry is required: call ExpiresAt(...) or ExpiresIn(...)")
	}
	if exp <= iat {
		return 0, fmt.Errorf("attestation exp (%d) must be after iat (%d)", exp, iat)
	}
	return exp, nil
}

// privateJWKMembers are the JWK members that carry private or secret key material (RFC 7518 section 6).
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// confirmationJWKMembers are the public members a cnf.jwk of each key type must carry.
var confirmationJWKMembers = map[string][]string{"EC": {"crv", "x", "y"}, "RSA": {"n", "e"}}

// confirmationJWK returns the public key to bind as cnf.jwk: kty, the key type's public members and an
// optional kid, copied from in. It refuses a JWK with private or secret members, an unsupported kty or
// curve, or a missing member, so a private key is never signed into an attestation.
func confirmationJWK(in map[string]any) (map[string]any, error) {
	for _, m := range privateJWKMembers {
		if _, ok := in[m]; ok {
			return nil, fmt.Errorf("cnf.jwk must be a public key: it carries the private member %q", m)
		}
	}
	kty, _ := in["kty"].(string)
	required, ok := confirmationJWKMembers[kty]
	if !ok {
		return nil, fmt.Errorf("cnf.jwk must be an EC or RSA public key, not kty %q", kty)
	}
	out := map[string]any{"kty": kty}
	for _, m := range required {
		v, _ := in[m].(string)
		if v == "" {
			return nil, fmt.Errorf("cnf.jwk (kty %s) is missing %q", kty, m)
		}
		out[m] = v
	}
	if crv, _ := out["crv"].(string); kty == "EC" && crv != "P-256" && crv != "P-384" && crv != "P-521" {
		return nil, fmt.Errorf("cnf.jwk curve must be P-256, P-384 or P-521, not %q", crv)
	}
	if kid, present := in["kid"]; present {
		s, _ := kid.(string)
		if s == "" {
			return nil, fmt.Errorf("cnf.jwk kid must be a non-empty string")
		}
		out["kid"] = s
	}
	return out, nil
}

// PopBuilder builds a Client Attestation PoP JWT proving possession of the
// instance key. Client side of attest_jwt_client_auth; mint a fresh one per
// token request and sign it with the instance key.
type PopBuilder struct {
	instanceKey *SigningKeyPair
	clientID    string
	audience    string
	challenge   string
	jwtID       string
	issuedAt    *int64
}

// NewPopBuilder starts a PoP builder signing with instanceKey.
func NewPopBuilder(instanceKey *SigningKeyPair) *PopBuilder {
	return &PopBuilder{instanceKey: instanceKey}
}

// ClientID sets the optional "iss" (= client_id).
func (b *PopBuilder) ClientID(clientID string) *PopBuilder {
	b.clientID = clientID
	return b
}

// Audience sets the AS identifier this PoP is bound to ("aud") — required.
func (b *PopBuilder) Audience(audience string) *PopBuilder {
	b.audience = audience
	return b
}

// Challenge sets the optional server challenge.
func (b *PopBuilder) Challenge(challenge string) *PopBuilder {
	b.challenge = challenge
	return b
}

// JwtID sets an explicit "jti" (otherwise a random UUID is used).
func (b *PopBuilder) JwtID(jwtID string) *PopBuilder {
	b.jwtID = jwtID
	return b
}

// IssuedAt sets an explicit "iat" (epoch seconds).
func (b *PopBuilder) IssuedAt(epochSeconds int64) *PopBuilder {
	b.issuedAt = &epochSeconds
	return b
}

// Build signs and returns the compact PoP JWT.
func (b *PopBuilder) Build() (string, error) {
	if _, err := requireText(b.audience, "audience (aud)"); err != nil {
		return "", err
	}
	iat := time.Now().Unix()
	if b.issuedAt != nil {
		iat = *b.issuedAt
	}
	jti := b.jwtID
	if jti == "" {
		jti = uuid.NewString()
	}
	claims := map[string]any{
		"aud": b.audience,
		"jti": jti,
		"iat": iat,
	}
	if b.clientID != "" {
		claims["iss"] = b.clientID
	}
	if b.challenge != "" {
		claims["challenge"] = b.challenge
	}
	return b.instanceKey.signCompact(claims, PopTyp, false)
}

// DpopProofBuilder builds a DPoP proof JWT (RFC 9449) for attestation combined
// mode (PoP method dpop_combined): the embedded "jwk" header MUST be the
// instance key bound in the attestation's cnf. Sign with the instance key.
type DpopProofBuilder struct {
	instanceKey *SigningKeyPair
	htm         string
	htu         string
	nonce       string
	accessToken string
	jwtID       string
	issuedAt    *int64
}

// NewDpopProofBuilder starts a DPoP builder signing with instanceKey; htm
// defaults to "POST".
func NewDpopProofBuilder(instanceKey *SigningKeyPair) *DpopProofBuilder {
	return &DpopProofBuilder{instanceKey: instanceKey, htm: "POST"}
}

// Method sets the request HTTP method ("htm"); blank is ignored. It is upper-cased at Build.
func (b *DpopProofBuilder) Method(htm string) *DpopProofBuilder {
	if htm != "" {
		b.htm = htm
	}
	return b
}

// URI sets the target URL ("htu") — required. At Build it is normalised per RFC 9449 §4.2 by the rule
// in vectors/README.md: the userinfo, query, fragment and a default port are dropped and the scheme and
// host lower-cased. Build refuses a URL that is not an absolute http(s) URL with a valid ASCII host,
// port and path, or that has a backslash, ASCII whitespace or a control character before its query or
// fragment.
func (b *DpopProofBuilder) URI(htu string) *DpopProofBuilder {
	b.htu = htu
	return b
}

// Nonce sets the optional server challenge, carried in DPoP "nonce".
func (b *DpopProofBuilder) Nonce(nonce string) *DpopProofBuilder {
	b.nonce = nonce
	return b
}

// AccessToken binds the proof to an access token: "ath" = base64url(SHA-256(token)) (RFC 9449 §4.2).
// Required when presenting a DPoP-bound token at a resource; omit at the token endpoint.
func (b *DpopProofBuilder) AccessToken(token string) *DpopProofBuilder {
	b.accessToken = token
	return b
}

// JwtID sets an explicit "jti" (otherwise a random UUID is used).
func (b *DpopProofBuilder) JwtID(jwtID string) *DpopProofBuilder {
	b.jwtID = jwtID
	return b
}

// IssuedAt sets an explicit "iat" (epoch seconds).
func (b *DpopProofBuilder) IssuedAt(epochSeconds int64) *DpopProofBuilder {
	b.issuedAt = &epochSeconds
	return b
}

// Build signs and returns the compact DPoP proof JWT.
func (b *DpopProofBuilder) Build() (string, error) {
	if _, err := requireText(b.htu, "uri (htu)"); err != nil {
		return "", err
	}
	htu, err := normalizeHTU(b.htu)
	if err != nil {
		return "", err
	}
	iat := time.Now().Unix()
	if b.issuedAt != nil {
		iat = *b.issuedAt
	}
	jti := b.jwtID
	if jti == "" {
		jti = uuid.NewString()
	}
	claims := map[string]any{
		"htm": strings.ToUpper(b.htm),
		"htu": htu,
		"jti": jti,
		"iat": iat,
	}
	if b.nonce != "" {
		claims["nonce"] = b.nonce
	}
	if b.accessToken != "" {
		claims["ath"] = accessTokenHash(b.accessToken)
	}
	return b.instanceKey.signCompact(claims, DpopTyp, true)
}

package clientattestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// ecdsaGenerate creates a fresh ECDSA private key for the named JWK curve.
func ecdsaGenerate(crv string) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// rsaGenerate creates a fresh RSA private key of the given bit size.
func rsaGenerate(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

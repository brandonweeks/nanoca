package nanoca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"
)

// decideUnattested is validateChallenge's verdict for a device-attest-01
// answer without an attestation object: the UnattestedAuthorizer stands in
// for the verifier and the Authorizer.
func (ca *CA) decideUnattested(ctx context.Context, challenge *Challenge, authz *Authorization) (func(*Challenge), error) {
	authorized, err := ca.unattested.AuthorizeUnattested(ctx, UnattestedRequest{
		Identifier:  authz.Identifier,
		AccountID:   authz.AccountID,
		OrderID:     authz.OrderID,
		ChallengeID: challenge.ID,
	})
	if err != nil {
		ca.logger.ErrorContext(ctx, "Unattested authorization check failed", "challenge_id", challenge.ID, "error", err)
		// Only the text, not the chain: a gate error is a backend
		// condition, even a *Problem.
		return nil, fmt.Errorf("unattested authorizer: %s", err.Error())
	}
	if !authorized {
		ca.logger.WarnContext(ctx, "Unattested device not authorized", "challenge_id", challenge.ID)
		return nil, Unauthorized("Device not authorized for certificate issuance")
	}
	return func(c *Challenge) { c.settleValidUnattested(time.Now()) }, nil
}

// checkCSRKeyUnattested holds the CSR key of an unattested order to a
// minimum strength, since no attestation vouches for it: ECDSA P-256, P-384
// or P-521, or RSA of at least 2048 bits. Like checkCSRKeyAttested it
// returns badCSR, so the order stays ready for a stronger key.
func checkCSRKeyUnattested(csr *x509.CertificateRequest) error {
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521() {
			return nil
		}
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return nil
		}
	}
	return BadCSR("CSR key must be ECDSA P-256 or stronger, or RSA of at least 2048 bits, for a device without attestation")
}

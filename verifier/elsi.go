package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/verifiable"
)

var ErrorNoKidHeader = errors.New("no_kid_header")
var ErrorEmptyCertChain = errors.New("empty_certificate_chain")
var ErrorPemDecodeFailed = errors.New("pem_decode_failed")
var ErrorNoCertChain = errors.New("no_cert_chain")

type JAdESValidator interface {
	ValidateSignature(payload, signature []byte) (bool, error)
}

func NewJAdESJWTProofChecker(
	defaultChecker *checker.ProofChecker, jAdESValidator JAdESValidator) verifiable.CombinedProofChecker {
	return &JAdESJWTProofChecker{defaultChecker, jAdESValidator}
}

type JAdESJWTProofChecker struct {
	defaultChecker *checker.ProofChecker
	jAdESValidator JAdESValidator
}

func (jpc JAdESJWTProofChecker) CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	kid, exists := headers.KeyID()
	if !exists {
		return ErrorNoKidHeader
	}
	method := strings.Split(kid, ":")[1]
	if method == "elsi" {
		return jpc.checkElsiProof(headers, expectedProofIssuer, msg, signature)
	} else {
		return jpc.defaultChecker.CheckJWTProof(headers, expectedProofIssuer, msg, signature)
	}
}

func (jpc JAdESJWTProofChecker) CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error {
	return jpc.defaultChecker.CheckLDProof(proof, expectedProofIssuer, msg, signature)
}

func (jpc JAdESJWTProofChecker) GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return jpc.defaultChecker.GetLDPCanonicalDocument(proof, doc, opts...)
}

func (jpc JAdESJWTProofChecker) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	return jpc.defaultChecker.GetLDPDigest(proof, doc)
}

func (jpc JAdESJWTProofChecker) checkElsiProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	isValid, err := jpc.jAdESValidator.ValidateSignature(msg, signature)
	if !isValid || err != nil {
		logging.Log().Warnf("JAdES signature is invalid. Err: %v", err)
		return err
	}

	certificate, err := retrieveCertificate(headers)

	return validateControlOfDID(certificate, expectedProofIssuer)
}

func retrieveCertificate(headers jose.Headers) (*x509.Certificate, error) {
	raw, ok := headers[jose.HeaderX509CertificateChain]
	if !ok {
		return nil, ErrorNoCertChain
	}

	chain, ok := raw.([]string)

	if len(chain) != 0 {
		return parseCertificate(chain[0])
	} else {
		return nil, ErrorEmptyCertChain
	}
}

func parseCertificate(certBase64 string) (*x509.Certificate, error) {
	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return nil, ErrorPemDecodeFailed
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func validateControlOfDID(certificate *x509.Certificate, issuerDid string) error {
	var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	var organizationIdentifier string

	for _, name := range certificate.Subject.Names {
		if name.Type.Equal(oidOrganizationIdentifier) {
			organizationIdentifier = name.Value.(string)
			break
		}
	}

	parts := strings.Split(issuerDid, ":")
	if len(parts) != 3 {
		return errors.New("invalid did")
	}

	if parts[0] == "did" && parts[1] == "elsi" && parts[2] == organizationIdentifier {
		return nil
	} else {
		return errors.New("did validation failed")
	}
}

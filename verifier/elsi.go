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

const DidElsiPrefix = "did:elsi:"
const DidPartsSeparator = ":"

var ErrorEmptyCertChain = errors.New("empty_certificate_chain")
var ErrorPemDecodeFailed = errors.New("pem_decode_failed")
var ErrorNoCertChain = errors.New("no_cert_chain")
var ErrorDidValidationFailed = errors.New("did_validation_failed")

type JAdESValidator interface {
	ValidateSignature(signature string) (bool, error)
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
	if isDidElsiMethod(expectedProofIssuer) {
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
	decodedMsg, err := decodeBase64BytesToString(msg)
	if err != nil {
		logging.Log().Warnf("Error decoding msg: %v", err)
		return err
	}

	jwt := decodedMsg + "." + base64.RawURLEncoding.EncodeToString(signature)
	logging.Log().Infof("JWT: %s", jwt)

	base64Jwt := base64.RawURLEncoding.EncodeToString([]byte(jwt))
	isValid, err := jpc.jAdESValidator.ValidateSignature(base64Jwt)
	if !isValid || err != nil {
		logging.Log().Warnf("JAdES signature is invalid. Err: %v", err)
		return err
	}

	certificate, err := retrieveCertificate(headers)
	if certificate == nil || err != nil {
		return err
	}

	return validateControlOfDID(certificate, expectedProofIssuer)
}

func decodeBase64BytesToString(base64Bytes []byte) (string, error) {
	base64Str := base64.RawURLEncoding.EncodeToString(base64Bytes)
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return "", err
	}

	return string(decodedBytes[:]), nil
}

func retrieveCertificate(headers jose.Headers) (*x509.Certificate, error) {
	raw, ok := headers[jose.HeaderX509CertificateChain]
	if !ok {
		return nil, ErrorNoCertChain
	}

	rawArray := raw.([]interface{})

	if len(rawArray) != 0 {
		cert := rawArray[0].(string)
		return parseCertificate(cert)
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

func isDidElsiMethod(did string) bool {
	parts := strings.Split(did, DidPartsSeparator)
	return len(parts) == 3 && strings.HasPrefix(did, DidElsiPrefix)
}

func validateControlOfDID(certificate *x509.Certificate, issuerDid string) error {
	var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	organizationIdentifier := ""

	for _, name := range certificate.Subject.Names {
		if name.Type.Equal(oidOrganizationIdentifier) {
			organizationIdentifier = name.Value.(string)
			break
		}
	}

	if organizationIdentifier != "" && strings.HasSuffix(issuerDid, DidPartsSeparator+organizationIdentifier) {
		return nil
	} else {
		return ErrorDidValidationFailed
	}
}

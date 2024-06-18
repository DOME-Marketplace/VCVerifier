package verifier

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/bbs"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ecdsa"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/ed25519"
	"github.com/trustbloc/vc-go/crypto-ext/verifiers/rsa"
	"github.com/trustbloc/vc-go/proof/checker"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es256k"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es384"
	"github.com/trustbloc/vc-go/proof/jwtproofs/es521"
	"github.com/trustbloc/vc-go/proof/jwtproofs/ps256"
	"github.com/trustbloc/vc-go/proof/jwtproofs/rs256"
	"github.com/trustbloc/vc-go/proof/ldproofs/bbsblssignature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/ecdsasecp256k1signature2019"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2018"
	"github.com/trustbloc/vc-go/proof/ldproofs/ed25519signature2020"
	"github.com/trustbloc/vc-go/proof/ldproofs/jsonwebsignature2020"
)

var ErrorNoKidHeader = errors.New("no_kid_header")
var ErrorUntrustedX5C = errors.New("untrusted_x5c")

type DomeJWTProofChecker struct {
	defaultChecker         *checker.ProofChecker
	certificateFingerprint string
}

func NewDomeJWTProofChecker(certificateFingerprint string) DomeJWTProofChecker {

	defaultChecker := checker.New(
		JWTVerfificationMethodResolver{},
		checker.WithSignatureVerifiers(
			ed25519.New(),
			bbs.NewBBSG2SignatureVerifier(),
			rsa.NewPS256(),
			rsa.NewRS256(),
			ecdsa.NewSecp256k1(),
			ecdsa.NewES256(),
			ecdsa.NewES384(),
			ecdsa.NewES521()),
		checker.WithLDProofTypes(
			bbsblssignature2020.New(),
			ecdsasecp256k1signature2019.New(),
			ed25519signature2018.New(),
			ed25519signature2020.New(),
			jsonwebsignature2020.New(),
		),
		checker.WithJWTAlg(es256.New(),
			es256k.New(),
			es384.New(),
			es521.New(),
			rs256.New(),
			ps256.New()),
	)

	if certificateFingerprint == "" {
		logging.Log().Fatal("No certificate fingerprint is provided, we would not be able to verify any DOME credentials.")
		panic("no_certificate_fingerprint_configured")
	}

	return DomeJWTProofChecker{defaultChecker: defaultChecker, certificateFingerprint: certificateFingerprint}

}

// extension of the default JWT Proof Check to support Jades-Signatures(either as part of did:elsi or as plain x5c header)
func (dpc DomeJWTProofChecker) CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	kid, exists := headers.KeyID()
	if !exists {
		return ErrorNoKidHeader
	}
	x5c, x5cExists := headers["x5c"]
	prefix := strings.Split(kid, ":")[0]
	if prefix != "did" && x5cExists {
		return dpc.checkElsiProof(msg, signature, x5c)
	}
	method := strings.Split(kid, ":")[1]
	if method == "elsi" {
		return dpc.checkElsiProof(msg, signature, x5c)
	} else {
		return dpc.defaultChecker.CheckJWTProof(headers, expectedProofIssuer, msg, signature)
	}
}

func (dpc DomeJWTProofChecker) CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error {
	return dpc.defaultChecker.CheckLDProof(proof, expectedProofIssuer, msg, signature)
}

func (dpc DomeJWTProofChecker) GetLDPCanonicalDocument(proof *proof.Proof, doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	return dpc.defaultChecker.GetLDPCanonicalDocument(proof, doc, opts...)
}

func (dpc DomeJWTProofChecker) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	return dpc.defaultChecker.GetLDPDigest(proof, doc)
}

func (dpc DomeJWTProofChecker) checkElsiProof(msg, signature []byte, x5c interface{}) error {

	x5cString := x5c.([]interface{})[0].(string)

	cert, err := base64.RawStdEncoding.DecodeString(x5cString)
	if err != nil {
		logging.Log().Warnf("Was not able to decode the x5c. %v", err)
		return err
	}
	parsedCert, err := x509.ParseCertificate(cert)
	if err != nil {
		logging.Log().Warnf("Was not able to parse the x5c. %v", err)
		return err
	}

	fingerprint := buildCertificateFingerprint(parsedCert)

	if fingerprint != dpc.certificateFingerprint {
		logging.Log().Warn("The credential was not signed with the trusted certificate.")
		return ErrorUntrustedX5C
	}

	err = parsedCert.CheckSignature(x509.SHA256WithRSA, msg, signature)
	if err != nil {
		logging.Log().Warnf("Signature is invalid. %v", err)
	}
	return err
}

func buildCertificateFingerprint(certificate *x509.Certificate) (fingerprint string) {

	fingerprintBytes := sha256.Sum256(certificate.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprintBytes {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}

	return buf.String()
}

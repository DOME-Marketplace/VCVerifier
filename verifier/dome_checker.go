package verifier

import (
	"errors"
	"strings"

	"github.com/trustbloc/did-go/doc/ld/processor"
	"github.com/trustbloc/did-go/doc/ld/proof"
	"github.com/trustbloc/kms-go/doc/jose"
	"github.com/trustbloc/vc-go/proof/checker"
)

var ErrorNoKidHeader = errors.New("no_kid_header")

type DomeJWTProofChecker struct {
	defaultChecker *checker.ProofChecker
}

func (dpc DomeJWTProofChecker) CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	kid, exists := headers.KeyID()
	if !exists {
		return ErrorNoKidHeader
	}
	method := strings.Split(kid, ":")[1]
	if method == "elsi" {
		return checkElsiProof(headers, expectedProofIssuer, msg, signature)
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

func checkElsiProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {

	return nil
}

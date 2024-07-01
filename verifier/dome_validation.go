package verifier

import (
	"strings"

	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
)

/**
* Workaround service for the DOME shortcomings. Will allow all issuers with schema did:elsi
 */
type DomeValidationService struct{}

func (tpvs *DomeValidationService) ValidateVC(verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {
	if strings.HasPrefix(verifiableCredential.Contents().Issuer.ID, "did:elsi:") {
		return true, err
	} else {
		logging.Log().Infof("Only did:elsi is directly trusted through the preconfigured cert, not %s", verifiableCredential.Contents().Issuer.ID)
		return false, err
	}
}

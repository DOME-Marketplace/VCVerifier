package verifier

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"github.com/fiware/VCVerifier/logging"
	"github.com/trustbloc/vc-go/verifiable"
	"strings"
)

type JAdESValidator interface {
	ValidateCertificate(certificate *x509.Certificate, chain []*x509.Certificate) (bool, error)
	ValidateSignature(signature string) (bool, error)
}

type ElsiValidationService struct {
	validator JAdESValidator
}

func (vs *ElsiValidationService) ValidateVC(
	verifiableCredential *verifiable.Credential, validationContext ValidationContext) (result bool, err error) {
	logging.Log().Debugf("Validating credential %s with JAdES certificate",
		logging.PrettyPrintObject(verifiableCredential))

	jadesContext := validationContext.(JAdESValidationContext)
	isValid, err := vs.validator.ValidateCertificate(jadesContext.GetCertificate(), jadesContext.GetChain())
	if !isValid || err != nil {
		logging.Log().Warnf("eIDAS certificate is invalid. Err: %v", err)
		return false, err
	}

	isValid, err = vs.validator.ValidateSignature(jadesContext.GetSignature())
	if !isValid || err != nil {
		logging.Log().Warnf("JAdES signature is invalid. Err: %v", err)
		return false, err
	}

	return validateControlOfDID(jadesContext.GetCertificate(), verifiableCredential.Contents().Issuer.ID)
}

func validateControlOfDID(certificate *x509.Certificate, did string) (bool, error) {
	var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}
	var organizationIdentifier string

	for _, name := range certificate.Subject.Names {
		if name.Type.Equal(oidOrganizationIdentifier) {
			organizationIdentifier = name.Value.(string)
			break
		}
	}

	parts := strings.Split(did, ":")
	if len(parts) != 3 {
		return false, errors.New("invalid did")
	}

	return parts[0] == "did" && parts[1] == "elsi" && parts[2] == organizationIdentifier, nil
}

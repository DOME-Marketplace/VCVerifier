package dss

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	client "github.com/fiware/dsba-pdp/http"
)

const ValidationIndicationPassed = "PASSED"
const ValidationIndicationTotalPassed = "TOTAL_PASSED"

var ErrorDSSSignatureValidationFailed = errors.New("signature_validation_failed")
var ErrorDSSResponseNotOk = errors.New("dss_response_not_ok")
var ErrorDSSEmptyResponseBody = errors.New("dss_empty_response_body")

type ExternalJAdESValidator struct {
	signatureValidationUrl string
}

type RemoteDocument struct {
	Bytes           *string `json:"bytes"`
	DigestAlgorithm *string `json:"digestAlgorithm"`
	Name            *string `json:"name"`
}

type signatureValidationRequest struct {
	SignedDocument          *RemoteDocument   `json:"signedDocument"`
	OriginalDocuments       []*RemoteDocument `json:"originalDocuments"`
	Policy                  *RemoteDocument   `json:"policy"`
	EvidenceRecords         []*RemoteDocument `json:"evidenceRecords"`
	TokenExtractionStrategy *string           `json:"tokenExtractionStrategy"`
	SignatureId             *string           `json:"signatureId"`
}

type ValidationPolicy struct {
	PolicyName        *string
	PolicyDescription *string
}

type Signature struct {
	SignatureFormat *string
	SignedBy        *string
	Indication      *string
	SubIndication   *string
}

type SignatureOrTimestampOrEvidenceRecord struct {
	Signature *Signature
}

type SimpleReport struct {
	ValidationPolicy                     *ValidationPolicy
	DocumentName                         *string
	SignatureOrTimestampOrEvidenceRecord []*SignatureOrTimestampOrEvidenceRecord `json:"signatureOrTimestampOrEvidenceRecord"`
}

type validationResponse struct {
	ValidationReportDataHandler *string       `json:"validationReportDataHandler"`
	SimpleReport                *SimpleReport `json:"simpleReport"`
}

var httpClient = client.HttpClient()

func InitDSSJAdESValidator(configuration *config.Configuration) (*ExternalJAdESValidator, error) {
	jAdESConfig := configuration.JAdES
	validator := &ExternalJAdESValidator{jAdESConfig.SignatureValidationAddress}
	return validator, nil
}

func (c *ExternalJAdESValidator) ValidateSignature(signature string) (bool, error) {
	logging.Log().Infof("Validate signature %s", signature)

	signatureName := "JAdES"
	tokenExtractionStrategy := "NONE"

	validationRequest := signatureValidationRequest{
		&RemoteDocument{Bytes: &signature, DigestAlgorithm: nil, Name: &signatureName},
		nil,
		nil,
		nil,
		&tokenExtractionStrategy,
		nil,
	}
	jsonBody, err := json.Marshal(validationRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to marshal validation request body. Err: %v", err)
		return false, err
	}
	validationHttpRequest, err := http.NewRequest("POST", c.signatureValidationUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		logging.Log().Warnf("Was not able to create validation request. Err: %v", err)
		return false, err
	}
	validationHttpRequest.Header.Set("Content-Type", "application/json")
	validationHttpRequest.Header.Set("Accept", "application/json")
	validationHttpResponse, err := httpClient.Do(validationHttpRequest)

	if err != nil {
		logging.Log().Warnf("Did not receive a valid validation response. Err: %v", err)
		return false, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logging.Log().Warnf("Was not able to close the response body. Err: %v", err)
		}
	}(validationHttpResponse.Body)

	if validationHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from DSS. Was %s", logging.PrettyPrintObject(validationHttpResponse))
		return false, ErrorDSSResponseNotOk
	}
	if validationHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body on the validation.")
		return false, ErrorDSSEmptyResponseBody
	}
	validationResponse := &validationResponse{}

	err = json.NewDecoder(validationHttpResponse.Body).Decode(validationResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the validation response.")
		return false, err
	}
	logging.Log().Info(validationResponse)
	if isValidationSuccessful(*validationResponse) {
		return true, nil
	} else {
		logging.Log().Info("Validation failed.")
		logging.Log().Debugf("Detailed result is %v", logging.PrettyPrintObject(validationResponse))
		return false, ErrorDSSSignatureValidationFailed
	}
}

func isValidationSuccessful(response validationResponse) bool {
	for _, item := range response.SimpleReport.SignatureOrTimestampOrEvidenceRecord {
		if !(*item.Signature.Indication == ValidationIndicationPassed ||
			*item.Signature.Indication == ValidationIndicationTotalPassed) ||
			item.Signature.SubIndication != nil {
			return false
		}
	}
	return true
}

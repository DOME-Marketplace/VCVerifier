package dss

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	client "github.com/fiware/dsba-pdp/http"
)

const ValidationIndicationPassed = "PASSED"

var ErrorDSSNoResponse = errors.New("no_response_from_dss")
var ErrorDSSSignatureValidationFailed = errors.New("signature_validation_failed")
var ErrorDSSResponseNotOk = errors.New("dss_response_not_ok")
var ErrorDSSEmptyResponseBody = errors.New("dss_empty_response_body")

type ExternalJAdESValidator struct {
	signatureValidationUrl string
}

type CertificatePayload struct {
	EncodedCertificate string `json:"encodedCertificate"`
}

type RemoteDocument struct {
	Bytes           string `json:"bytes"`
	DigestAlgorithm string `json:"digestAlgorithm"`
	Name            string `json:"name"`
}

type signatureValidationRequest struct {
	SignedDocument          *RemoteDocument  `json:"signedDocument"`
	OriginalDocuments       []RemoteDocument `json:"originalDocuments"`
	Policy                  *RemoteDocument  `json:"policy"`
	EvidenceRecords         []RemoteDocument `json:"evidenceRecords"`
	TokenExtractionStrategy string           `json:"tokenExtractionStrategy"`
	SignatureId             *string          `json:"signatureId"`
}

type ValidationPolicy struct {
	PolicyName        string
	PolicyDescription string
}

type ChainItem struct {
	Id            string   `json:"id"`
	IssuerId      string   `json:"issuerId"`
	KeyUsage      []string `json:"keyUsage"`
	Indication    string
	SubIndication *string
}

type SimpleCertificateReport struct {
	ValidationPolicy *ValidationPolicy
	ChainItem        []ChainItem
	ValidationTime   *time.Time
}

type validationResponse struct {
	SimpleCertificateReport *SimpleCertificateReport `json:"simpleCertificateReport"`
}

var httpClient = client.HttpClient()

func InitDSSJAdESValidator(configuration *config.Configuration) (*ExternalJAdESValidator, error) {
	jAdESConfig := configuration.JAdES
	validator := &ExternalJAdESValidator{jAdESConfig.SignatureValidationAddress}
	return validator, nil
}

func (c *ExternalJAdESValidator) ValidateSignature(payload, signature []byte) (bool, error) {
	logging.Log().Debugf("Validate signature %s for payload %s", string(signature), string(payload))

	validationRequest := signatureValidationRequest{
		&RemoteDocument{Bytes: string(signature), Name: "JAdES"},
		[]RemoteDocument{
			{Bytes: string(payload), Name: "VerifiableCredential"},
		},
		nil,
		nil,
		"NONE",
		nil,
	}
	jsonBody, err := json.Marshal(validationRequest)
	if err != nil {
		logging.Log().Warnf("Was not able to marshal validation request body. Err: %v", err)
		return false, err
	}
	validationHttpRequest, err := http.NewRequest("POST", c.signatureValidationUrl, bytes.NewReader(jsonBody))
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
	if validationHttpResponse == nil {
		logging.Log().Warn("Did not receive any response from DSS.")
		return false, ErrorDSSNoResponse
	}
	if validationHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from DSS. Was %s", logging.PrettyPrintObject(validationHttpResponse))
		return false, ErrorDSSResponseNotOk
	}
	if validationHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body on the validation.")
		return false, ErrorDSSEmptyResponseBody
	}
	var validationResponse validationResponse

	err = json.NewDecoder(validationHttpResponse.Body).Decode(&validationResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the validation response.")
		return false, err
	}
	if isValidationSuccessful(validationResponse) {
		return true, nil
	} else {
		logging.Log().Info("Validation failed.")
		logging.Log().Debugf("Detailed result is %v", logging.PrettyPrintObject(validationResponse))
		return false, ErrorDSSSignatureValidationFailed
	}
}

func isValidationSuccessful(response validationResponse) bool {
	for _, item := range response.SimpleCertificateReport.ChainItem {
		if item.Indication != ValidationIndicationPassed || item.SubIndication != nil {
			return false
		}
	}
	return true
}

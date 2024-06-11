package dss

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"net/http"
	"time"

	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	client "github.com/fiware/dsba-pdp/http"
)

type ExternalJAdESValidator struct {
	certificateValidationUrl string
	signatureValidationUrl   string
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

var ErrorDSSNoResponse = errors.New("no_response_from_dss")
var httpClient = client.HttpClient()

func InitDSSJAdESValidator(configuration *config.Configuration) (*ExternalJAdESValidator, error) {
	jAdESConfig := configuration.JAdES
	validator := &ExternalJAdESValidator{
		certificateValidationUrl: jAdESConfig.CertificateValidationAddress,
		signatureValidationUrl:   jAdESConfig.SignatureValidationAddress,
	}
	return validator, nil
}

func (c *ExternalJAdESValidator) ValidateSignature(payload, signature []byte) (bool, error) {
	logging.Log().Debugf("Validate signature %s", signature)

	jwtPayload, err := getPayloadFromJwt(string(signature))
	if err != nil {
		logging.Log().Warnf("Was not able to marshal validation request body. Err: %v", err)
		return false, err
	}

	validationRequest := signatureValidationRequest{
		&RemoteDocument{Bytes: string(signature), Name: "jades.json"},
		[]RemoteDocument{
			{Bytes: jwtPayload, Name: "vc"},
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
		logging.Log().Warnf("Was not able to create verification request. Err: %v", err)
		return false, err
	}
	validationHttpRequest.Header.Set("Content-Type", "application/json")
	validationHttpRequest.Header.Set("accept", "application/json")
	validationHttpResponse, err := httpClient.Do(validationHttpRequest)

	if err != nil {
		logging.Log().Warnf("Did not receive a valid verification response. Err: %v", err)
		return false, err
	}
	if validationHttpResponse == nil {
		logging.Log().Warn("Did not receive any response from ssikit.")
		return false, ErrorDSSNoResponse
	}
	if validationHttpResponse.StatusCode != 200 {
		logging.Log().Infof("Did not receive an ok from the verifier. Was %s", logging.PrettyPrintObject(validationHttpResponse))
		return false, err
	}
	if validationHttpResponse.Body == nil {
		logging.Log().Info("Received an empty body on the verification.")
		return false, err
	}
	var validationResponse validationResponse

	err = json.NewDecoder(validationHttpResponse.Body).Decode(&validationResponse)
	if err != nil {
		logging.Log().Warn("Was not able to decode the  verification response.")
		return false, err
	}
	if isValidationSuccessful(validationResponse) {
		return true, err
	} else {
		logging.Log().Info("Validation failed.")
		logging.Log().Debugf("Detailed result is %v", logging.PrettyPrintObject(validationResponse))
		return false, err
	}
}

func isValidationSuccessful(response validationResponse) bool {
	for _, item := range response.SimpleCertificateReport.ChainItem {
		if item.Indication != "PASSED" || item.SubIndication != nil {
			return false
		}
	}
	return true
}

func getPayloadFromJwt(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid token")
	}
	return parts[1], nil
}

package verifier

import (
	"crypto/x509"
	"encoding/base64"
	"github.com/fiware/VCVerifier/logging"
	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/vc-go/verifiable"
	"log"
	"testing"
)

type mockExternalValidator struct {
	certValid      bool
	signatureValid bool
}

const ValidEidasCert = "MIIHAjCCBOqgAwIBAgIUVJpNAg7fr4imrRq8a57UkBxx95IwDQYJKoZIhvcNAQELBQAwZDELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjESMBAGA1UECgwJRklXQVJFIENBMRIwEAYDVQQDDAlGSVdBUkUtQ0ExHDAaBgkqhkiG9w0BCQEWDWNhQGZpd2FyZS5vcmcwHhcNMjQwNTA3MTIxNjE5WhcNMjkwNTA2MTIxNjE5WjCBpjELMAkGA1UEBhMCREUxDzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMRowGAYDVQQKDBFGSVdBUkUgRm91bmRhdGlvbjEUMBIGA1UEAwwLRklXQVJFLVRlc3QxHjAcBgkqhkiG9w0BCQEWD3Rlc3RAZml3YXJlLm9yZzELMAkGA1UEBRMCMDMxFjAUBgNVBGEMDVZBVERFXzEyMzQ1NjcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy1n/x92jsPttVHwnIdkRhWxZszBl7AY5ACCXoS9CnU2sgbtbx+ijA+6dPJ8Q6rTrCCuldww/8BBkYW6jZdPD+/777WnMuFwWqpQl+priCv3J3iAFMYvnMzJk8fVWtUjiOZYFGvXMXmj50NSawRKoq/2i8oo5OsU+FnPEyMdsfmdgC/VyxorBJO1zw48Sl1g2sRedwzKfeKfGa4yT8dg3nRqYw1fORdjaX3GtHwL/rD9ZhZwQH7Tss6Q688cc0k1fyJRj5nKdVKCRDxSyLzGP/+6ecGA2Subv0Hb8Dw1uvKqfeZ+0/ZUDZm85IOBqBflYkMG2nB4GrWpHw8CCVq55xz+5TOCwzVjXyy5gQ2MNofn6owPOJyOvUN5KPIyfWH7U2rb2Pe5t7EtZxwvaWWy42CpLrYYPcfVC+RkPj+BF4plmR3wr9/0NMdrapxSCmXTvrxWrUcOT/KoUMTjG5uNF72yESjUvIi0kG28Y+fRinOOx6bMfzFacC7QY6wrRIwDDcrAGaa/EGTTK4FAk/c74zA2wr/J/nimEDmWU3dpesG91OpWoiDb6H72NXQ+OsrWdyOniYPzrqGNC/BYtXQLC84dDwBVEtmxniICeBp/JgwJk4WFmgEmCuCVVW+QMKKemxs0MD5pPn/jwvHN/g49g3iyYQ/cVdk0I2fU9NhY3UXQIDAQABo4IBZzCCAWMwgZ4GCCsGAQUFBwEDBIGRMIGOMAgGBgQAjkYBATA4BgYEAI5GAQUwLjAsFiFodHRwczovL2V4YW1wbGUub3JnL3BraWRpc2Nsb3N1cmUTB2V4YW1wbGUwIQYGBACBmCcCMBcMDFNvbWUgdGVzdCBDQQwHWFgtREZTQTAlBgYEAI5GAQYwGwYHBACORgEGAQYHBACORgEGAgYHBACORgEGAzAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIFoDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0ZWQgQ2xpZW50IENlcnRpZmljYXRlMB0GA1UdDgQWBBRA6U9DlDO9XvGWzNzfZKHJEAdd9DAfBgNVHSMEGDAWgBQE5d5G3LeBRY76N7b8GzwJWyKdyzAOBgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0GCSqGSIb3DQEBCwUAA4ICAQA20xwHZDj6FEWkAJDZS0QsyNBIJ/s7IBRAn/71kPh5VmZqj7SDql0yUTEz7BxqLbYAqrasihWOB7gATzYxVDafTgEHtXf54YVgjhSjxY7ITIP3t0GZEX4t/Ewu68Whpzz0u6ALLDETYydjNh2rIuohvFQh8VLc6kY7yA0z/EEvi1EvymMQLJHSuskSOOBII6dypnhcL8vh9n+lqS4qr37ZzSGD5h7SpYMggGCqHGr14b5AZYHLSLx2gnuop8F3ZViBvw/cWiRRaqkWrfktHb5br6aVvR/wgjl3+h+wOS9lbpKHIMNku7foI7j15sALHxJOh30WmUKIA8I3Iee77T2weVyw+Y247dqevm0ANmnfdjoZgsEz6C7BWKbeT+F45hs32+7j/hzEzrr2IrVX//LryPPRF3CC4wgNHNIv/0Oh0qnfmWxj9MIVwVsGeQQBfgmlT56uD9qyGyd8LMal3AYOhVroCSL88Xn4pmlO0k6GWdG1RCiMpF+vuGPbQBflSXnkKgcSb4rfak5KATVl0AuLtyeAWQcw4DWldnC8cCCdBIpW9kpzQkGOocoDnbY0QmKcqQq0SXhV+pFDDBqW3hjbFe0ltH+05CRNyrGE/1tJMyvue6TKYEGyM3dK2vpYM9xYFqMLDnhQ/b0Ngdpr5Ugk5zvp1IdCd/WEe4HCDl94Gw=="
const SameIssuer = "did:elsi:VATDE_1234567"
const OtherIssuer = "did:elsi:VATDE_999"

var AnyValidCertChain []*x509.Certificate
var AnyValidSignature = "VALID"

func (c *mockExternalValidator) ValidateCertificate(_ *x509.Certificate, _ []*x509.Certificate) (bool, error) {
	return c.certValid, nil
}

func (c *mockExternalValidator) ValidateSignature(_ string) (bool, error) {
	return c.signatureValid, nil
}

func TestJadesValidationService_ValidateVC(t *testing.T) {
	type testCase struct {
		testName            string
		credentialToVerify  verifiable.Credential
		verificationContext ValidationContext
		certValid           bool
		signatureValid      bool
		expectedResult      bool
	}

	validationContext := JAdESValidationContext{
		certificate: parseCertificate(ValidEidasCert),
		chain:       AnyValidCertChain,
		signature:   AnyValidSignature,
	}

	testCases := []testCase{
		{
			testName:            "A credential with valid JAdES signature should be successfully validated",
			credentialToVerify:  getCredentialWithJades(SameIssuer),
			verificationContext: validationContext,
			certValid:           true,
			signatureValid:      true,
			expectedResult:      true,
		},
		{
			testName:            "A credential with invalid JAdES signature should be rejected",
			credentialToVerify:  getCredentialWithJades(SameIssuer),
			verificationContext: validationContext,
			certValid:           true,
			signatureValid:      false,
			expectedResult:      false,
		},
		{
			testName:            "A credential with invalid eIDAS certificate should be rejected",
			credentialToVerify:  getCredentialWithJades(SameIssuer),
			verificationContext: validationContext,
			certValid:           false,
			signatureValid:      true,
			expectedResult:      false,
		},
		{
			testName:            "A credential with valid JAdES signature from different issuer should be rejected",
			credentialToVerify:  getCredentialWithJades(OtherIssuer),
			verificationContext: validationContext,
			certValid:           true,
			signatureValid:      true,
			expectedResult:      false,
		},
	}

	externalValidator := &mockExternalValidator{}
	validationService := &ElsiValidationService{validator: externalValidator}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestJadesValidationService_ValidateVC +++++++ Running test: ", tc.testName)
			externalValidator.certValid = tc.certValid
			externalValidator.signatureValid = tc.signatureValid

			actualResult, err := validationService.ValidateVC(&tc.credentialToVerify, tc.verificationContext)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedResult, actualResult)
		})
	}
}

func getCredentialWithJades(issuer string) verifiable.Credential {
	vc, _ := verifiable.CreateCredential(verifiable.CredentialContents{
		Issuer: &verifiable.Issuer{ID: issuer},
	}, verifiable.CustomFields{})
	return *vc
}

func parseCertificate(certBase64 string) *x509.Certificate {
	certDER, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		log.Fatal(err)
		return nil
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return cert
}

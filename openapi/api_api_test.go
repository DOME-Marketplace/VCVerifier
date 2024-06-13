package openapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/logging"
	verifier "github.com/fiware/VCVerifier/verifier"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"github.com/trustbloc/vc-go/proof/defaults"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
)

type mockVerifier struct {
	mockJWTString        string
	mockQR               string
	mockConnectionString string
	mockAuthRequest      string
	mockJWKS             jwk.Set
	mockOpenIDConfig     common.OpenIDProviderMetadata
	mockSameDevice       verifier.SameDeviceResponse
	mockExpiration       int64
	mockError            error
}

func (mV *mockVerifier) ReturnLoginQR(host string, protocol string, callback string, sessionId string, clientId string) (qr string, err error) {
	return mV.mockQR, mV.mockError
}
func (mV *mockVerifier) StartSiopFlow(host string, protocol string, callback string, sessionId string, clientId string) (connectionString string, err error) {
	return mV.mockConnectionString, mV.mockError
}
func (mV *mockVerifier) StartSameDeviceFlow(host string, protocol string, sessionId string, redirectPath string, clientId string) (authenticationRequest string, err error) {
	return mV.mockAuthRequest, mV.mockError
}
func (mV *mockVerifier) GetToken(authorizationCode string, redirectUri string) (jwtString string, expiration int64, err error) {
	return mV.mockJWTString, mV.mockExpiration, mV.mockError
}
func (mV *mockVerifier) GetJWKS() jwk.Set {
	return mV.mockJWKS
}
func (mV *mockVerifier) AuthenticationResponse(state string, presentation *verifiable.Presentation) (sameDevice verifier.SameDeviceResponse, err error) {
	return mV.mockSameDevice, mV.mockError
}
func (mV *mockVerifier) GetOpenIDConfiguration(serviceIdentifier string) (metadata common.OpenIDProviderMetadata, err error) {
	return mV.mockOpenIDConfig, err
}

func (mV *mockVerifier) GenerateToken(clientId, subject, audience string, scope []string, presentation *verifiable.Presentation) (int64, string, error) {
	return mV.mockExpiration, mV.mockJWTString, mV.mockError
}

type mockExternalValidator struct {
	signatureValid bool
}

func (c *mockExternalValidator) ValidateSignature(_ string) (bool, error) {
	return c.signatureValid, nil
}

func TestGetToken(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		testGrantType      string
		testCode           string
		testRedirectUri    string
		testVPToken        string
		testScope          string
		mockJWTString      string
		mockExpiration     int64
		mockError          error
		expectedStatusCode int
		expectedResponse   TokenResponse
		expectedError      ErrorMessage
	}
	tests := []test{
		{testName: "If a valid authorization_code request is received a token should be responded.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockJWTString: "theJWT", mockExpiration: 10, mockError: nil, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}, expectedError: ErrorMessage{}},
		{testName: "If no grant type is provided, the request should fail.", testGrantType: "", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessagNoGrantType},
		{testName: "If an invalid grant type is provided, the request should fail.", testGrantType: "my_special_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageUnsupportedGrantType},
		{testName: "If no auth code is provided, the request should fail.", testGrantType: "authorization_code", testCode: "", testRedirectUri: "http://my-redirect.org", expectedStatusCode: 400, expectedError: ErrorMessageNoCode},
		{testName: "If no redirect uri is provided, the request should fail.", testGrantType: "authorization_code", testCode: "my-auth-code", expectedStatusCode: 400, expectedError: ErrorMessageNoRedircetUri},
		{testName: "If the verify returns an error, a 403 should be answerd.", testGrantType: "authorization_code", testCode: "my-auth-code", testRedirectUri: "http://my-redirect.org", mockError: errors.New("invalid"), expectedStatusCode: 403, expectedError: ErrorMessage{}},

		{testName: "If a valid vp_token request is received a token should be responded.", testGrantType: "vp_token", testVPToken: getValidVPToken(), testScope: "tir_read", mockJWTString: "theJWT", mockExpiration: 10, expectedStatusCode: 200, expectedResponse: TokenResponse{TokenType: "Bearer", ExpiresIn: 10, AccessToken: "theJWT"}},
		{testName: "If no valid vp_token is provided, the request should fail.", testGrantType: "vp_token", testScope: "tir_read", expectedStatusCode: 400, expectedError: ErrorMessageNoToken},
		{testName: "If no valid scope is provided, the request should fail.", testVPToken: getValidVPToken(), testGrantType: "vp_token", expectedStatusCode: 400, expectedError: ErrorMessageNoScope},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {
			presentationOptions = []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockJWTString: tc.mockJWTString, mockExpiration: tc.mockExpiration, mockError: tc.mockError}

			formArray := []string{}

			if tc.testGrantType != "" {
				formArray = append(formArray, "grant_type="+tc.testGrantType)
			}
			if tc.testCode != "" {
				formArray = append(formArray, "code="+tc.testCode)
			}
			if tc.testRedirectUri != "" {
				formArray = append(formArray, "redirect_uri="+tc.testRedirectUri)
			}

			if tc.testScope != "" {
				formArray = append(formArray, "scope="+tc.testScope)
			}

			if tc.testVPToken != "" {
				formArray = append(formArray, "vp_token="+tc.testVPToken)
			}

			body := bytes.NewBufferString(strings.Join(formArray, "&"))
			testContext.Request, _ = http.NewRequest("POST", "/", body)
			testContext.Request.Header.Add("Content-Type", gin.MIMEPOSTForm)

			GetToken(testContext)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}

			if tc.expectedStatusCode == 400 {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				json.Unmarshal(errorBody, &errorMessage)
				if errorMessage != tc.expectedError {
					t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
					return
				}
				return
			}

			tokenResponse := TokenResponse{}
			if tc.expectedResponse != tokenResponse {
				body, _ := io.ReadAll(recorder.Body)
				err := json.Unmarshal(body, &tokenResponse)
				if err != nil {
					t.Errorf("%s - Was not able to unmarshal the token response. Err: %v.", tc.testName, err)
					return
				}
				if tokenResponse != tc.expectedResponse {
					t.Errorf("%s - Expected token response %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedResponse), logging.PrettyPrintObject(tokenResponse))
					return
				}
			}
		})

	}
}

func TestStartSIOPSameDevice(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		testState          string
		testRedirectPath   string
		testRequestAddress string
		mockRedirect       string
		mockError          error
		expectedStatusCode int
		expectedLocation   string
	}

	tests := []test{
		{"If all neccessary parameters provided, a valid redirect should be returned.", "my-state", "/my-redirect", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 302, "http://host.org/api/v1/authentication_response"},
		{"If no path is provided, the default redirect should be returned.", "my-state", "", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 302, "http://host.org/api/v1/authentication_response"},
		{"If no state is provided, a 400 should be returned.", "", "", "http://host.org", "http://host.org/api/v1/authentication_response", nil, 400, ""},
		{"If the verifier returns an error, a 500 should be returned.", "my-state", "/", "http://host.org", "http://host.org/api/v1/authentication_response", errors.New("verifier_failure"), 500, ""},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {
			presentationOptions = []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockAuthRequest: tc.mockRedirect, mockError: tc.mockError}

			testParameters := []string{}
			if tc.testState != "" {
				testParameters = append(testParameters, "state="+tc.testState)
			}
			if tc.testRedirectPath != "" {
				testParameters = append(testParameters, "redirect_path="+tc.testRedirectPath)
			}

			testContext.Request, _ = http.NewRequest("GET", tc.testRequestAddress+"/?"+strings.Join(testParameters, "&"), nil)
			StartSIOPSameDevice(testContext)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}
			if tc.expectedStatusCode != 302 {
				// everything other is an error, we dont care about the details
				return
			}

			location := recorder.Result().Header.Get("Location")
			if location != tc.expectedLocation {
				t.Errorf("%s - Expected location %s but was %s.", tc.testName, tc.expectedLocation, location)
			}
		})
	}
}

func TestVerifierAPIAuthenticationResponse(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName               string
		sameDevice             bool
		testState              string
		testVPToken            string
		mockError              error
		mockSameDeviceResponse verifier.SameDeviceResponse
		expectedStatusCode     int
		expectedRedirect       string
		expectedError          ErrorMessage
	}

	tests := []test{
		{"If a same-device flow is authenticated, a valid redirect should be returned.", true, "my-state", getValidVPToken(), nil, verifier.SameDeviceResponse{RedirectTarget: "http://my-verifier.org", Code: "my-code", SessionId: "my-session-id"}, 302, "http://my-verifier.org?state=my-session-id&code=my-code", ErrorMessage{}},
		{"If a cross-device flow is authenticated, a simple ok should be returned.", false, "my-state", getValidVPToken(), nil, verifier.SameDeviceResponse{}, 200, "", ErrorMessage{}},
		{"If the same-device flow responds an error, a 400 should be returend", true, "my-state", getValidVPToken(), errors.New("verification_error"), verifier.SameDeviceResponse{}, 400, "", ErrorMessage{Summary: "verification_error"}},
		{"If no state is provided, a 400 should be returned.", true, "", getValidVPToken(), nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageNoState},
		{"If an no token is provided, a 400 should be returned.", true, "my-state", "", nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageNoToken},
		{"If a token with invalid credentials is provided, a 400 should be returned.", true, "my-state", getNoVCVPToken(), nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageUnableToDecodeToken},
		{"If a token with an invalid holder is provided, a 400 should be returned.", true, "my-state", getNoHolderVPToken(), nil, verifier.SameDeviceResponse{}, 400, "", ErrorMessageUnableToDecodeToken},
	}

	for _, tc := range tests {

		t.Run(tc.testName, func(t *testing.T) {

			//presentationOptions = []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}
			presentationOptions = []verifiable.PresentationOpt{
				verifiable.WithPresProofChecker(defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{})),
				verifiable.WithPresJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockSameDevice: tc.mockSameDeviceResponse, mockError: tc.mockError}

			formArray := []string{}

			if tc.testVPToken != "" {
				formArray = append(formArray, "vp_token="+tc.testVPToken)
			}

			requestAddress := "http://my-verifier.org/"
			if tc.testState != "" {
				formArray = append(formArray, "state="+tc.testState)
			}

			body := bytes.NewBufferString(strings.Join(formArray, "&"))
			testContext.Request, _ = http.NewRequest("POST", requestAddress, body)
			testContext.Request.Header.Add("Content-Type", gin.MIMEPOSTForm)

			VerifierAPIAuthenticationResponse(testContext)

			if tc.expectedStatusCode == 400 {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				json.Unmarshal(errorBody, &errorMessage)
				if errorMessage != tc.expectedError {
					t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
					return
				}
				return
			}

			if tc.sameDevice && tc.expectedStatusCode != 302 && tc.expectedStatusCode != recorder.Code {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}

			if tc.sameDevice {
				location := recorder.Result().Header.Get("Location")
				if location != tc.expectedRedirect {
					t.Errorf("%s - Expected location %s but was %s.", tc.testName, tc.expectedRedirect, location)
					return
				}
				return
			}

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected status %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}
			if tc.expectedStatusCode != 200 {
				return
			}
		})
	}
}

func TestVerifierAPIStartSIOP(t *testing.T) {

	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName                 string
		testState                string
		testCallback             string
		testAddress              string
		mockConnectionString     string
		mockError                error
		expectedStatusCode       int
		expectedConnectionString string
		expectedError            ErrorMessage
	}

	tests := []test{
		{"If all parameters are present, a siop flow should be started.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 200, "openid://mockConnectionString", ErrorMessage{}},
		{"If no state is present, a 400 should be returned.", "", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, "", ErrorMessageNoState},
		{"If no callback is present, a 400 should be returned.", "my-state", "", "http://my-verifier.org", "openid://mockConnectionString", nil, 400, "", ErrorMessageNoCallback},
		{"If the verifier cannot start the flow, a 500 should be returend.", "my-state", "http://my-callback.org", "http://my-verifier.org", "openid://mockConnectionString", errors.New("verifier_failure"), 500, "", ErrorMessageNoState},
	}

	for _, tc := range tests {

		logging.Log().Info("TestVerifierAPIStartSIOP +++++++++++++++++ Running test: ", tc.testName)

		t.Run(tc.testName, func(t *testing.T) {
			presentationOptions = []verifiable.PresentationOpt{verifiable.WithPresDisabledProofCheck(), verifiable.WithDisabledJSONLDChecks()}

			recorder := httptest.NewRecorder()
			testContext, _ := gin.CreateTestContext(recorder)
			apiVerifier = &mockVerifier{mockConnectionString: tc.mockConnectionString, mockError: tc.mockError}

			testParameters := []string{}
			if tc.testState != "" {
				testParameters = append(testParameters, "state="+tc.testState)
			}
			if tc.testCallback != "" {
				testParameters = append(testParameters, "client_callback="+tc.testCallback)
			}

			testContext.Request, _ = http.NewRequest("GET", tc.testAddress+"/?"+strings.Join(testParameters, "&"), nil)
			VerifierAPIStartSIOP(testContext)

			if recorder.Code != tc.expectedStatusCode {
				t.Errorf("%s - Expected code %v but was %v.", tc.testName, tc.expectedStatusCode, recorder.Code)
				return
			}
			if tc.expectedStatusCode == 500 {
				// something internal, we dont care about the details
				return
			}

			if tc.expectedStatusCode == 400 {
				errorBody, _ := io.ReadAll(recorder.Body)
				errorMessage := ErrorMessage{}
				json.Unmarshal(errorBody, &errorMessage)
				if errorMessage != tc.expectedError {
					t.Errorf("%s - Expected error %s but was %s.", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(errorMessage))
					return
				}
				return
			}
			body, _ := io.ReadAll(recorder.Body)
			connectionString := string(body)
			if connectionString != tc.expectedConnectionString {
				t.Errorf("%s - Expected connectionString %s but was %s.", tc.testName, tc.expectedConnectionString, connectionString)
			}
		})
	}
}

func TestExtractVpFromToken(t *testing.T) {
	recorder := httptest.NewRecorder()
	testContext, _ := gin.CreateTestContext(recorder)
	jAdESValidator := &mockExternalValidator{true}
	presentationOptions = []verifiable.PresentationOpt{
		verifiable.WithPresProofChecker(verifier.NewJAdESJWTProofChecker(
			defaults.NewDefaultProofChecker(verifier.JWTVerfificationMethodResolver{}), jAdESValidator)),
		verifiable.WithPresJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))}
	validVpToken := "ewogICJAY29udGV4dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwKICAidHlwZSI6IFsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLAogICJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6IFsiZXlKaGJHY2lPaUpTVXpJMU5pSXNJbU4wZVNJNkltcHpiMjRpTENKcmFXUWlPaUpOU1VkQlRVZHBhMXBxUW10TlVYTjNRMUZaUkZaUlVVZEZkMHBGVWxSRlVFMUJNRWRCTVZWRlEwRjNSMUZ0Vm5saVIyeDFUVkpKZDBWQldVUldVVkZMUkVGc1IxTldaRUpWYTFWblVUQkZlRVZxUVZGQ1owNVdRa0ZOVFVOVldrcFdNRVpUVWxNeFJGRlVSV05OUW05SFExTnhSMU5KWWpORVVVVktRVkpaVGxreVJrRmFiV3d6V1ZoS2JFeHRPWGxhZDBsVlNXdHJXR0p6VEhOMGFVeG1aV1Z0YTNZeUsySlFVRVF5VlRSclBTSXNJbmcxZENOVE1qVTJJam9pTlRWM1EwRnNUbTV4TURNMmVFaHNSakppV2poWFp6WlJjVXRPUWpaNGNEWkJVR3RUYURKYWVXUXdUU0lzSW5nMVl5STZXeUpOU1VsSVQycERRMEpUUzJkQmQwbENRV2RKVlVscmExaGljMHh6ZEdsTVptVmxiV3QyTWl0aVVGQkVNbFUwYTNkRVVWbEtTMjlhU1doMlkwNUJVVVZNUWxGQmQxcEVSVXhOUVd0SFFURlZSVUpvVFVOU1JWVjRSSHBCVGtKblRsWkNRV2ROUW10S2JHTnRlSEJpYWtWVFRVSkJSMEV4VlVWRFozZEtVbXRzV0ZGV1NrWkpSVTVDVFZKSmQwVkJXVVJXVVZGRVJFRnNSMU5XWkVKVmExVjBVVEJGZUVoRVFXRkNaMnR4YUd0cFJ6bDNNRUpEVVVWWFJGZE9hRkZIV25Ca01rWjVXbE0xZG1OdFkzZElhR05PVFdwUmQwNXFSWGxOUkdOM1RsUkJNMWRvWTA1TmFtdDNUbXBGZUUxRVkzZE9WRUV6VjJwRFFuQnFSVXhOUVd0SFFURlZSVUpvVFVOU1JWVjRSSHBCVGtKblRsWkNRV2ROUW10S2JHTnRlSEJpYWtWUVRVRXdSMEV4VlVWQ2QzZEhVVzFXZVdKSGJIVk5VbTkzUjBGWlJGWlJVVXRFUWtaSFUxWmtRbFZyVldkU2JUa3hZbTFTYUdSSGJIWmlha1ZWVFVKSlIwRXhWVVZCZDNkTVVtdHNXRkZXU2taTVZsSnNZek5SZUVocVFXTkNaMnR4YUd0cFJ6bDNNRUpEVVVWWFJETlNiR016VWtGYWJXd3pXVmhLYkV4dE9YbGFla1ZNVFVGclIwRXhWVVZDVWsxRFRVUk5lRVpxUVZWQ1owNVdRa2RGVFVSV1drSldSVkpHVEZSRmVVMTZVVEZPYW1OM1oyZEphVTFCTUVkRFUzRkhVMGxpTTBSUlJVSkJVVlZCUVRSSlEwUjNRWGRuWjBsTFFXOUpRMEZSUkVGS1pUVkJhbEJWYlU1M1ozVlZWblZKTVZZeVRTdFljazV0Um1NM05WQlNNSFJzVUV3NWJFUkxSMkZKTkRaVlRYTk1Obk5wWVZGVFZURlpWMVVyVURGbFRYUXpWSEowZFhoS1ZrNXdUbVZCUm1rNVJXcExaM1ppVldoWFUweE9SemhTVld0SVptdE5RbEp0VmpkQlVVazFlRWhYUzFWWVJ6TnJlVTVLUlZacGJWbFhSa0Z0YWxaWWF5dHhSRU5tV2tKTlVpODVNamRJZDNwWWRtRmpaUzl6VFdsUEsza3pkRXB1TUhReU4wOW5kRlJuWTJndk5WaHlSWFprU2tWRU1uVnZLMnAzWTJobGNWVkpVV3BSUW5SaWFYbGpXV0pTTVVkalJqVnVVMHRZZFU5alVrdEVaMWN5ZEZBdlMwTlNiakZNVlc5cksyWmxVbWszY0hoWFR6TnZRV3hwZEVwblZTdEZWR1pXTVhBNGNHSm5UWFowVFdkM1FrTnhVbE42Y2xkTWFHaFNkRzFqVTBkM1JrRmxkVFpPWnpCa01pc3hjWGRuTUhkMVJIWklaRmMyZUdwV2IyNXpMMFowTmpZeVEyeGpWa1puZEhrdlpuZFhlaXRDTXpGVWRsbFRjRFlyTjFsbGN5dHhkM05oYjBoMUsxcG9lbmhaYWpWa2FWWXpjREZwZVhSVWFYZFNVa2QwYnpSNGNEZG1WRkJsUldadFpFcHJVVXhpZEVOM2NYcE5lVlF3VFRaWlFubEpPQ3Q0UVVSV05uaFJTR2x1VFhORGR6aFdhSEExT1ZoQk1UUjRNa3d4TkVocldHZzRPWGxaTUcxeFZ6TkNlRTR6SzAxVGFtbEtWRE5IVWxwYVRrRkVTalpHU3pZNE1ubEdXbXh6UmtOcVpURnpiM1paZGxsSVZHSjBMMnRxZWtGcFIzRlNiRzg1YkhKeFdESlNTRXczVEcxRlVXaElORFpGY0ROWlpVb3JaMEpqT0ZSalNVRTBkaXQ2VFdKU2RYSm1PVk5PVHpRdmFWUnBPRTQzWmpaTVNFZG9aVGxFYlZoWE1HWXhUMDlzY2xadWR6VlhTMDA1Y3pCMUwwZHlha0U0ZGtoRUwwOVphQzlpUjBGM1ZuWmxMMGRNYm5JeWVETnJkRVpOVjJwdVMxSlFhbFJsV1ZwSmNuYzFRMFk0WmpWSlVuSmxkSGgyYUhGVk9GQm9kM2RSU1VSQlVVRkNielJKUW01NlEwTkJXbk4zWjFvMFIwTkRjMGRCVVZWR1FuZEZSRUpKUjFKTlNVZFBUVUZuUjBKblVVRnFhMWxDUVZSQk5FSm5XVVZCU1RWSFFWRlZkMHhxUVhOR2FVWnZaRWhTZDJONmIzWk1NbFkwV1ZjeGQySkhWWFZpTTBwdVRETkNjbUZYVW5Cak1rNXpZak5PTVdOdFZWUkNNbFkwV1ZjeGQySkhWWGRKVVZsSFFrRkRRbTFEWTBOTlFtTk5SRVpPZG1KWFZXZGtSMVo2WkVOQ1JGRlJkMGhYUm1kMFVrVmFWRkZVUVd4Q1oxbEZRVWsxUjBGUldYZEhkMWxJUWtGRFQxSm5SVWRCVVZsSVFrRkRUMUpuUlVkQloxbElRa0ZEVDFKblJVZEJla0ZLUW1kT1ZraFNUVVZCYWtGQlRVSkZSME5YUTBkVFFVZEhLMFZKUWtGUlVVVkJkMGxHYjBSQmVrSm5iR2RvYTJkQ2FIWm9RMEZSTUVWS2FGbHJWRE5DYkdKc1RsUlVRMEpJV2xjMWJHTnRSakJhVjFGblVUSjRjRnBYTlRCSlJVNXNZMjVTY0ZwdGJHcFpXRkpzVFVJd1IwRXhWV1JFWjFGWFFrSlJTRUUyYzFoUWQxUmhhM05STlZCdmNtZ3paRlIwVUdSc1ZHTnFRV1pDWjA1V1NGTk5SVWRFUVZkblFsUndWVkZzVjFwQkswWlVUWE5pWVZJeFdHVlNSbmhMVFhaVlUwUkJUMEpuVGxaSVVUaENRV1k0UlVKQlRVTkNaVUYzU0ZGWlJGWlNNR3hDUWxsM1JrRlpTVXQzV1VKQ1VWVklRWGRKUjBORGMwZEJVVlZHUW5kTlJVMUVXVWRCTVZWa1NIZFJkazFETUhkTE5rRndiME5sUjBwWGFEQmtTRUUyVEhrNWMySXpVbk5QYWsxM1RVUkJkbUZYTlRCYVdFcDBXbGRTY0ZsWVVteE1iVTU1WWtNMWQxcFhNSGRFVVZsS1MyOWFTV2gyWTA1QlVVVk1RbEZCUkdkblNVSkJSRFZxZFZaTmFGTjFTQ3R6TnpaWFR6bHNaRkprWXpKQmVscE5iMkpaTDJwV1kwNDFlV1I0UmpKcE9USlNRV1pRZFRRNWEyRlNielJaWmpJM01DdG9OazlYTUdaNU1WcEZhMWQwVEhsVlZFRjFZMDlVVVVKQ2MybFdaVkI0UVU1Skt5OWxUekY1U0c1WVRpOTNZVll2THl0bU9XSlBTVXhTVVhwRE9HdDJTa0pYTDJKUlZHcHBSRWxyU3pKRlptOVJlVlJXWVU1dmVWSXlPRWw1Ympob1VHOVBUbmRDVldOcU9IQm5abTVIYVU1dmEySk5lVzVKVDBoNkswSTFOWEJLTDBsTVNDc3ZTV0ZXTWxaeFFtczROMkpzZDBkRWQxQlJlbFE0Y1ZCU1VDdDZaa1ZQYW1aS2RrZ3pPRWcwV1d4eVFqZHRjemN6TDNSeWJpODRiWGhGSzFaME1IQnBaR1J0U0hoR1RHWjJNMkZ6Y2xaclNXZHRhRUYzWlhsbU5XcFRhelF4ZUZWeU9WZEljbkpCVDJsclFrSkplazVZVUROMFFYcEROemRxVTNwa01tbE5SM1JPVVRkVE5VVm9jMFJET1RCUmREbHRZMEkyZDJobVlYcHJaSEk1YUUxWldYbHBjbE5RSzI5dmIyeEJaaTgzWXpCcWVsbFJibFZtZFc1dlowaE5SblJWTjA1RlNFTktSSHB5YjNRclkxTjRSV2hHWmxWRVRYcENOamM0ZWpkMGQyaFZNVm8wYm5aNGNDdHVTMGx0VG5wd01YQXlSMlFyVDJoNWF6TlVhRWRxUWxoVFIxRTJRbWxDZEhGS1VsVlhSWGh4YTFZd1FYZGlPVGRvVmpaWldTOTFlV05JYUZadlltMWFZbXN6YmxKcWRUTnNTVTFhV0hvcmVrUXhiVXBUYmxOV1NFbEVSREpQYmpkc01qZHhiblJLVFc1RFJGSlplamhqTTJ4NFVVUkZVMWwzU0VoUVIzcHlSVEJaZEZVMlNXOVpUV1YyWkRZME5VcEJMekpPVkRNeFZHeHdXREoyUzBzdmIwZFpiM1pZTlRsc1NYcGhiSFJMWVhCNVJta3dOWE5rVjNaVVNuUldhWEpsYlhkMWJHbHNSMVJzYkRoUllYZzRSVVpDVlZjdmJWcDJUMVZqWlZkUGJtMW1VRkpUZVZBM09WWmxPRlZET1hsM2JUZDZUMU0yV1VwcVdEY2lMQ0pOU1VsR2VVUkRRMEUzUTJkQmQwbENRV2RKUWtGVVFVNUNaMnR4YUd0cFJ6bDNNRUpCVVhOR1FVUkRRbWRxUlV4TlFXdEhRVEZWUlVKb1RVTlNSVlY0UkhwQlRrSm5UbFpDUVdkTlFtdEtiR050ZUhCaWFrVlFUVUV3UjBFeFZVVkNkM2RIVVcxV2VXSkhiSFZOVWtsM1JVRlpSRlpSVVV0RVFXeEhVMVprUWxWclZXZFJNRVY0UldwQlVVSm5UbFpDUVUxTlExVmFTbFl3UmxOU1V6RkVVVlJGWTAxQ2IwZERVM0ZIVTBsaU0wUlJSVXBCVWxsT1dUSkdRVnB0YkROWldFcHNURzA1ZVZwNlJVeE5RV3RIUVRGVlJVSlNUVU5OUkVWM1NHaGpUazFxVVhkT2FrVjVUVVJqZDA1VVFUSlhhR05PVFhwRmQwOVVSVEJOUkdOM1RsUkJNbGRxUW10TlVYTjNRMUZaUkZaUlVVZEZkMHBGVWxSRlVFMUJNRWRCTVZWRlEwRjNSMUZ0Vm5saVIyeDFUVkpKZDBWQldVUldVVkZMUkVGc1IxTldaRUpWYTFWblVUQkZlRVZxUVZGQ1owNVdRa0ZOVFVOVldrcFdNRVpUVWxNeFJGRlVSV05OUW05SFExTnhSMU5KWWpORVVVVktRVkpaVGxreVJrRmFiV3d6V1ZoS2JFeHRPWGxhZWtORFFXbEpkMFJSV1VwTGIxcEphSFpqVGtGUlJVSkNVVUZFWjJkSlVFRkVRME5CWjI5RFoyZEpRa0ZMUjNCVWVVeG1XVlZ6YWpoWGF6Vk1lRUk1Vkc1MU9HTnpRVFpqVlVrNVdHRjZTa0ZRWWpkVllUbFRibUZETW0xalZrUjNPVzlCU0hsUlJsZHpVMVEyVGxscFMzSnpabWxHYUcxMU9WVkhNalZEZG5VMGJuSmxNREJVTUhBNU1EQm9ZVGhuTlhCTWNWUkpSR1p4VGtsd1lqSXZNamwxVnl0MVpsTXZhMWhEVW1zMVdIaEtXVGhCYXl0RGQwbHBUVzAzZFVOV1dYZG1jbWR1V1N0clNsVTRUbmhzVEZadlpIcGliR3RqVldnMVVtVjRhRmhpTW5OMVdDOW9ZMUJWUVZodGN6SnlWVkJFTUVwNk1UWTFNRUZHYVhWbmFWZE1iVEpSUW5VeFZYWXhMekppWkhwdldVRlZkVEJITm0xTlNXcG5WMU52VGpOdVNIQlBRM2xZU2xOVE1sUTFXbWxKUW5jMVNuWkJjVzR4TW0xMksxbzNVbkZwTUc4dllqSllhbTg0TUdkSk9IWkZZVlp2UXpsRlkycFlkVmROYzBoSldqWk5XWGRUYTFOS2IyZE9ObGhEY1VsQldqTmpZVWxSVTBaRE9GbFRPVk16ZWxwTVZrbFdZVUpaVkM5UWFXTlhOekZQVGl0R1NXNUhjR2RQZWtWeWQzZzRNR04wTWl0NlEwaHFkamRYTkZKc2J5dENia1JyVEdZNU1qTmhObTl3YVRWWlVVSjVVa2xLUTI0d1RXWnNaVWhHT1RGcVNXWnlTMHhIUVhaMmRIWk9hamRuV1VwWmVHOHlhWGQ0ZGxRelR5OHhNMDFZYmpnd1JHeFNjRE5EUjFSUGJHWmpjakZsYTA5blR6UkVWamd6UWtwUU5rOXFhWFowUmxkU2RYbHpiRUZyTlhwSFFXZzJZVmxTU25WS2JXMHJSVEp1ZFdKSVpFUmpTbWRoZWxGeWRUbEJWbXRYYkhGMGJXOTVXR1k1ZGpWcE4wNWpjRzVNYVdkeE5IWXdhazVVYUZSWFdGQlJXVGhyUkRRNVVVZHJLMkZRWjI1NGQzcHdSa0ZTYWtoRWRrSmpWR0ZsV0dkU2RsRkZXVkEzYmtwdFYwbENRWGxOUXpJNVEweEtPVTB4WWpGU1RYVkNRM0IyVmxCMlQyZzJUakZaWjJGSGVETnJOMmhoVEVrNGNtODJkVFpQTVVZeVpYcFlPVWRyV0dKR056bFpOVUZuVFVKQlFVZHFXbXBDYTAxQ01FZEJNVlZrUkdkUlYwSkNWSEJWVVd4WFdrRXJSbFJOYzJKaFVqRllaVkpHZUV0TmRsVlRSRUZtUW1kT1ZraFRUVVZIUkVGWFowSlNORWhoVTA1cVJHVlNXbWMzV1ZCcVEyRTVjVFpoVDJoRlJXZFVRVk5DWjA1V1NGSk5Ra0ZtT0VWRFJFRkhRVkZJTDBGblJVRk5RVFJIUVRGVlpFUjNSVUl2ZDFGRlFYZEpRbWhxUVU1Q1oydHhhR3RwUnpsM01FSkJVWE5HUVVGUFEwRm5SVUZMY1VOd2FpOHJURVpEVERGU0swZDNTazFxV1ZwRmVERnlVbmR1VDBRelkycFZWbGROUjFWM1pXZEtjbFY2ZEdOeVEwSnRTbkY1UTJaVlREZHBaVFEwYTJ3eE5FaEVNa3R2VEN0Q2FIWlhiVGRMWm5NMk1EUllXVWxDWkdsUFpWbHBZVUo1WW1wcGMxSmFVRk5EWXpkcGRqbDVjSFZUZW1KemJtSlZlR3hIUlhaRWVqTmxjelJpVm1ST1FuTnlRVTlHTW1oS1pteGhhRTVyYkVwMVZWVmhjMWxPVGtjNWFEbENaamQ1ZWpoNmIwd3dURk4wY1RJNE5IWjVkM1ZoU1RCVlFXOVRkbmd2U0Vkd2FqSnlWbTR6ZEdST1pGWmxiRVJuZFhaRmEwTnhaVUZsYW1nNFdHMVVZbFI0TmpKUVNrUTFNelIwYzFZMFVWaDFWSHBVV1doTmJtcDNlbFo1WjAwek9FYzNTamhPVjI5TGN6UlhPSGhIVW1RMmRtYzVUMnBZTUU4clFuazFjVFJZWkhsNWJHeGhSVTQ1ZG01alRHSnRSVFZpVUd0cFZsUk5aMHBxUnpKamVHSjVTUzl5VUVaaWRFMVBLMjUwVjJ0bFJETlBNR2RXU1ZKUlZpOVNLMmx1YURKR2VVSm1SRU5qVTBaNUwwdFJVV3MzUkRZNWNVOWhPVEpUTW1OcVJGYzJZM2h0Ym1GdVFXUmthbGhPTUVKSE0ySXZiakowU0M5NVFubFVVMHAxU0RkNVVFTm9kV1IxY1hwVmJtRkZUa2xRYjAxRmEwODVhbEZyWmtaVVVrVlZNbHBZUzBKcFpGWXdRMjFvUWpWbldHZDJNR1p2Y2pkck4xZHljWEl5YlU5TWFVWkdRME5SUkdsWFJEY3lTRWRNTW1SMFJuWlVlV2t4WkRFdkszb3JOVkJzYnpCU1l6ZzViRzFyU1ZvelZUTjBXVU5sYlc0MWJHOVhNM2RHZGtJeldIWnNUM2xOWjNCWVFVVXZja2xaWXpSelVpdENWRFJNSzJFNEsybFpSMmRFUTFWUldWUndkMjF6WlhCclVVWmlUMFpCUkVwa01HYzRhbHBsVVZCdWVIcFBkSGRWYlVzdlNWWk9hMmhQUWxKUkwwZGlVVlU0U0U1aE9UWmlOVnByVEVZeWFqZzJPRU5qVGtWNlIySnFUR1pCZWxwd2NXNUNZVGgwU2tRMVRVMDViejBpTENKTlNVbEdNVVJEUTBFM2VXZEJkMGxDUVdkSlFrRlVRVTVDWjJ0eGFHdHBSemwzTUVKQlVYTkdRVVJEUW1kcVJVeE5RV3RIUVRGVlJVSm9UVU5TUlZWNFJIcEJUa0puVGxaQ1FXZE5RbXRLYkdOdGVIQmlha1ZRVFVFd1IwRXhWVVZDZDNkSFVXMVdlV0pIYkhWTlVrbDNSVUZaUkZaUlVVdEVRV3hIVTFaa1FsVnJWV2RSTUVWNFJXcEJVVUpuVGxaQ1FVMU5RMVZhU2xZd1JsTlNVekZFVVZSRlkwMUNiMGREVTNGSFUwbGlNMFJSUlVwQlVsbE9XVEpHUVZwdGJETlpXRXBzVEcwNWVWcDZSVXhOUVd0SFFURlZSVUpTVFVOTlJFVjNTR2hqVGsxcVVYZE9ha1Y1VFVSamQwNVVRVEZYYUdOT1RYcFJkMDVxUlhkTlJHTjNUbFJCTVZkcVEwSm5ha1ZNVFVGclIwRXhWVVZDYUUxRFVrVlZlRVI2UVU1Q1owNVdRa0ZuVFVKclNteGpiWGh3WW1wRlVFMUJNRWRCTVZWRlFuZDNSMUZ0Vm5saVIyeDFUVkpKZDBWQldVUldVVkZMUkVGc1IxTldaRUpWYTFWblVUQkZlRVZxUVZGQ1owNVdRa0ZOVFVOVldrcFdNRVpUVWxNeFJGRlVSV05OUW05SFExTnhSMU5KWWpORVVVVktRVkpaVGxreVJrRmFiV3d6V1ZoS2JFeHRPWGxhZWtWTVRVRnJSMEV4VlVWQ1VrMURUVVJGZDJkblNXbE5RVEJIUTFOeFIxTkpZak5FVVVWQ1FWRlZRVUUwU1VORWQwRjNaMmRKUzBGdlNVTkJVVVJJUkZkdldWZGFPVFZXWVRSTVN5dG1VMFJTYmxKclJIbDRVbFZ3TW5aeWJHaE9ObnA1TmpacFRGRTRNbFl5VkVaelVVNUdhMGxDV1RaMEsyaExZMFpxWTB4NFkwZHZaMWM0VkhaTFJrbHlRVTR6WkVKTFNEVmFkVzltVW00eWEyNTRSVlpWUkdSU2VucGhjRzlyVjNOc01UVnpSbmRhZHpWTVYyNUJUbmRMTVU4eGVHUnJlbVZTVTJGS2JIQlVTRGR5VVd0SVJsUkhWMnBzYkdGV1drdHJhM0ZPZDNwUVV6aFljMk5WWWs5eFNtUXhWM0JvTmxoc05IRkhVMk5QT1ZSVWQyUXpORlVyYUcxcVNqSmtVa1EwZGs5dk9UTXpVVlpNZFd4T1EwcE5hWFJhVnpWak1tZExObEU0ZFc5alZtOXBlbGROWlZRNVdsRldZelJwYW5Sd2NsWnplR05MY1Rsa1pDOWxZVFY1VFN0VFlXdzVjazFyTHpCclVERkhNMVp6SzNabVpsTk5hbG9yUkdGSVduZEVlRVZQTUdWWlFXa3ZiRU54YUVobGRtSlFSR1ZGZEZWcFNFSndXa0pYVDBsMVYxUjJWWGw2WlRWNFltUmtRVTQyWTJGWFpFb3pibEZKWVZKWFJqbDVlV2N5VEZKbVJsQndNekpRYldkblYzVkZNVlk1S3psVmVURlNURUk0UlZBeVMwbHJWV3BEU0c1aE9GSktVbEpvVFhGb09FWnhjRWhKZGl0bFQyVXdXbEpEUTBoRlNrUXZZbmQzTW1ONlpFaHlUM05hTW1kWmVIRTFjVTV0YlRSclYwMTNTMEZDV1VrNFdYbERkR3dyWlZOWVdXTkROVVI0Yld4eU9YQmhhVTVLVkhWNFZGZHJVa1YyVUhsak1qSXpNa1J2ZVRoVlJqQnFZV2R5U2xJeWRIaEZVRTgyU2xwVE5uUXpUa1owUnpoRFVGZHhiM3AwYkVGeVQxSkVReXRRUkhKRFRVZEdNbU12VFVwd1JIZHBWMVYyVVRBclZ6ZFZiMjFJYVZGR1ZETk9aWE40V25GdU4xbHVPVkkyWkVobE15dHdia3RUYVVKbFUxaHhhbWxZVHpOeGJVSk5NRU54T1ZweFlYSnNTVlJuVVVaUk5HUTBXakEyUlZnMFVIcFJlV3N3TW5oRlZYWjJWWFJvUjFVMmNETkNaRFZ2ZEVGU2VFWjNVVWxFUVZGQlFtOHhUWGRWVkVGa1FtZE9Wa2hSTkVWR1oxRlZaVUl5YTJwWmR6TnJWMWxQTWtRMGQyMTJZWFZ0YW05U1FrbEZkMGgzV1VSV1VqQnFRa0puZDBadlFWVmxRakpyYWxsM00ydFhXVTh5UkRSM2JYWmhkVzFxYjFKQ1NVVjNSSGRaUkZaU01GUkJVVWd2UWtGVmQwRjNSVUl2ZWtGT1FtZHJjV2hyYVVjNWR6QkNRVkZ6UmtGQlQwTkJaMFZCYWxoaWQzaG9Ta2RWVTBzdlZuTndUbUp3Wmsxck1tUmxlR2RNVTJaeWRteGFSRUZOY2tneVdsY3JXalJoVVUxRWRubGxiV3A2UzBabFQwSkllVVF2UVdZMWFVNU5lbE56YjFwWFlqRXdhRzFHV1ZkdWIwUlBNVVEzWTFaVlFXaE9iWFYxVWtReFpXSkJSa3BST1hKUVdYWjBMemxST0ZCTFJWUjFlREpIZEZGb1NuSllPR1psTjBNeWJuZEdWRmRFVjNoeWIzbFROR1phYWpSelJrVXZhSFpFZUdRemRtNDRNWHBEVTJsaEwyRTVaU3R5V25WclUxaFRUMXBzTVZnemNHNW1WMlJ2VlhWNVNqZ3dkQ3Q1YUdKMGIwWkhSVEpCVmxaVFdHb3JTSGxJVTJ0TFVVZDVTRzFvYTBKVFFtZ3JSa0pLTUZkcFVYQkhjVlpyV0hVelluVkVTMjVVSzJ4RVRVWlFPWFYzTUdSVGREbERTellyVGt0MlQyWm9UMVJVTlRKNVpGaFRMekZ3Ym1oTmNITnNXWFpXVTA5cmVYbEJOVVZWTTNvcmRVNU5TM1p4UlV0TUszQTNWWGR3U1ZZdmIwWllja2RHY2sxM2JUSXdTWFZZUTBOeFNWZ3hhRTB5TmxkWFZsbFdla293YlZSRWEwTnFiRE55VW5CSk9EWjViSGxRYnk5RGVGVjJaekUzU2s1NVdVdHplRWRqYWxwbFZWZFViV0ZOTVZjMVoxb3hOWE5ITDI1elZVZFNOVVZMUVVoNE0yRlBaUzlVUkZsTFZrUnVObWhhTURSQ1REVllNM1pxVUhoYU1qZHlVbkoyYlU0MlMyRkxRVmRrUmtFeE1tRm9jMEU1U1hseFFWTkRkWGw1YWpOVVJVcG9RbFpzVFhkcVpIQjFURXRFWkM4eVNYRjRZMmw0YldSV1VrOVBOVFJRTlZST1oyUkxNRmxZYjBkNE4zSm1XWGxQUXpSNlF6WnhiV3R5YWxscU9GSm5jbmx4VlVkQlQwSjFia0ZqT0hZNWJUUm1OVVZwWkVsWk5WaHFSR2M0T1RsMU5rNWFUbkl2YUdkamMxRnNTVk0wTVVvM2VVTkxOR2hYT0cwMWRYZFZiVTF5ZFU1TmNVRnFiMWRGVGk5UFFYcDZZWGRqTDIxTmEzSlJSa1Z0S3pBMVF5dHNhVFE1WTJoNFkwUnVNM0JFWVhObmJWaEVkVGc5SWwwc0luTnBaMVFpT2lJeU1ESTBMVEEyTFRFeVZERTJPalUyT2pVMFdpSXNJbU55YVhRaU9sc2ljMmxuVkNKZGZRLmV5SnVZbVlpT2pFM01UZ3lNVEUwTVRRc0ltcDBhU0k2SW5WeWJqcDFkV2xrT2pNNFltRXhPREF5TFRabVlqY3ROR1UzWVMwNU5qZGpMVEUyTURNMk9HWTRZV1V5TXlJc0ltbHpjeUk2SW1ScFpEcGxiSE5wT2xaQlZFUkZMVEV5TXpRMU5qY2lMQ0oyWXlJNmV5SjBlWEJsSWpwYklsWmxjbWxtYVdGaWJHVkRjbVZrWlc1MGFXRnNJbDBzSW1semMzVmxjaUk2SW1ScFpEcGxiSE5wT2xaQlZFUkZMVEV5TXpRMU5qY2lMQ0pwYzNOMVlXNWpaVVJoZEdVaU9qRTNNVGd5TVRFME1UUXhOek1zSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltWnBjbk4wVG1GdFpTSTZJazFoZUNJc0luSnZiR1Z6SWpwYmV5SnVZVzFsY3lJNld5Sk5lVkp2YkdVaVhTd2lkR0Z5WjJWMElqb2laR2xrT210bGVUb3hJbjFkTENKbVlXMXBiSGxPWVcxbElqb2lUWFZ6ZEdWeWJXRnViaUlzSW1WdFlXbHNJam9pZEdWemRFQjFjMlZ5TG05eVp5SjlMQ0pBWTI5dWRHVjRkQ0k2V3lKb2RIUndjem92TDNkM2R5NTNNeTV2Y21jdk1qQXhPQzlqY21Wa1pXNTBhV0ZzY3k5Mk1TSXNJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMMlY0WVcxd2JHVnpMM1l4SWwxOWZRLlJkS0lLVHZCNWhoMDJzTUF4elJlZF9zOXZ1WmpkYW8yODd4VmhCQkFUTjA4Mjh6Q2JNUVZkTXZGME1zbVcydUhyNHg0aGlJNkkwR2hiUTVpVkhzTGowY29VZTlRdjFocXVqM244dngzaGs0blc1dURoYUE1cVRlZ18tQklCOEZHMXRacmM2RVhBdVRxMW82djZneWVrSnhZOHpZeGtzZi1tTld3RVJuTkg3TEw2VmE4OGdfZ1BCZDBoS1dUZUNfZzNZcG5IVVBwek5FeXlIcWNXTnVzUlhPVlY1YUVZdzRnZDcwejVKcjFSWkg4V0V2QW1rUXlpZjB3b0F3MHBnQmUweDFxV2ZIZXd3YjZPS3lKOTVrWV9DQkxGMmh6NkYzZXNEOE1DYkxFS1ZEaE0tS01JeWlXUTh2MmttR3E5d0FwdGRMbGd2blgyM205Vm4wNU8tczdvTHRqaTBjbHV5MThsam9McUREalpFckYyWU1Hdjl1UUNrdng4cDBfZ3kzV3FCQkpjQ1hjeUpGaFB3dnhJV3BhQmtER0ZtYTJiZVVOOFhiM3pFYS1hcnotZjE2TEFTckJYWVUtMHZDdEx1V1BsNE95XzlzbVkxVGF2Nk9ZNkVIeGRRTXk5eEJUbE9lQ1RZYUxnVFRlQnZxYVNOVlpMNHE1VWZIVnpvSWxPb29HSUltTlFNa0NkY1pXLWlfWklFYlZ0T0FtWXhCMGl4ZWp1TDhSaUY0d1Z0a3FGblhRcndmM0JOUWlkdUR6dlZINHZzZnpSYjVSem5FTVMwWkgzelAtNVV2M0xuczM5eU9qSkVrVGhrU242QzZzUVluaF9DcnlyMnowcUxJR1I5cDBOc2QxS1Fla2c5dWU4MWpZRDJPUzV2SmJ5MUVTTXg3ZkFEX2Jqa0Y3VDRZIl0sCiAgImhvbGRlciI6ICJkaWQ6bXk6d2FsbGV0Igp9"

	_, err := extractVpFromToken(testContext, validVpToken)

	assert.NoError(t, err)
}

func getValidVPToken() string {
	return "eyJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJZ09pQWlTbGRVSWl3aWEybGtJaUE2SUNKa2FXUTZhMlY1T25wRWJtRmxWbGhVVGxGNVpEbFFaSE5oVmpOaGIySkdhMDFaYmxSMlNsSmplVFJCVVZKSWRVVTJaMUZ0T1ZOdFYwUWlmUS5leUp1WW1ZaU9qRTNNRGM1T0RRek1UQXNJbXAwYVNJNkluVnlhVHAxZFdsa09tTmlOV1k1WmpGakxUQXhOMkl0TkdRME5DMDRORFl4TFRjeVpETXlNMlJoT0RSalppSXNJbWx6Y3lJNkltUnBaRHByWlhrNmVrUnVZV1ZXV0ZST1VYbGtPVkJrYzJGV00yRnZZa1pyVFZsdVZIWktVbU41TkVGUlVraDFSVFpuVVcwNVUyMVhSQ0lzSW5OMVlpSTZJblZ5YmpwMWRXbGtPbVF5TUdZd09URmhMVGt4Wm1RdE5EZGhNaTA0WVRnM0xUUTFZamcyTURJMFltVTVaU0lzSW5aaklqcDdJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpWFN3aWFYTnpkV1Z5SWpvaVpHbGtPbXRsZVRwNlJHNWhaVlpZVkU1UmVXUTVVR1J6WVZZellXOWlSbXROV1c1VWRrcFNZM2swUVZGU1NIVkZObWRSYlRsVGJWZEVJaXdpYVhOemRXRnVZMlZFWVhSbElqb3hOekEzT1RnME16RXdPREV5TENKcFpDSTZJblZ5YVRwMWRXbGtPbU5pTldZNVpqRmpMVEF4TjJJdE5HUTBOQzA0TkRZeExUY3laRE15TTJSaE9EUmpaaUlzSW1OeVpXUmxiblJwWVd4VGRXSnFaV04wSWpwN0ltWnBjbk4wVG1GdFpTSTZJa2hoY0hCNVVHVjBjeUlzSW5KdmJHVnpJanBiZXlKdVlXMWxjeUk2V3lKSFQweEVYME5WVTFSUFRVVlNJaXdpVTFSQlRrUkJVa1JmUTFWVFZFOU5SVklpWFN3aWRHRnlaMlYwSWpvaVpHbGtPbXRsZVRwNk5rMXJjMVUyZEUxbVltRkVlblpoVW1VMWIwWkZOR1ZhVkZaVVZqUklTazAwWm0xUlYxZEhjMFJIVVZaelJYSWlmVjBzSW1aaGJXbHNlVTVoYldVaU9pSlFjbWx0WlNJc0ltbGtJam9pZFhKdU9uVjFhV1E2WkRJd1pqQTVNV0V0T1RGbVpDMDBOMkV5TFRoaE9EY3RORFZpT0RZd01qUmlaVGxsSWl3aWMzVmlhbVZqZEVScFpDSTZJbVJwWkRwM1pXSTZaRzl0WlMxdFlYSnJaWFJ3YkdGalpTNXZjbWNpTENKbmVEcHNaV2RoYkU1aGJXVWlPaUprYjIxbExXMWhjbXRsZEhCc1lXTmxMbTl5WnlJc0ltVnRZV2xzSWpvaWNISnBiV1V0ZFhObGNrQm9ZWEJ3ZVhCbGRITXViM0puSW4wc0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9pOHZkM2QzTG5jekxtOXlaeTh5TURFNEwyTnlaV1JsYm5ScFlXeHpMM1l4SWwxOWZRLlBqSVEtdEh5Zy1UZEdGTFVld1BreWc0cTJVODFkUGhpNG4wV3dXZ05KRGx3VW5mbk5OV1BIUkpDWlJnckQxMmFVYmRhakgtRlRkYTE3N21VRUd5RGZnIl0sImhvbGRlciI6ImRpZDp1c2VyOmdvbGQiLCJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdfQ"
}

func getNoVCVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAiaWQiOiAiZWJjNmYxYzIiLAogICJob2xkZXIiOiB7CiAgICAiaWQiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgiCiAgfSwKICAicHJvb2YiOiB7CiAgICAidHlwZSI6ICJKc29uV2ViU2lnbmF0dXJlMjAyMCIsCiAgICAiY3JlYXRvciI6ICJkaWQ6a2V5Ono2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiY3JlYXRlZCI6ICIyMDIzLTAxLTA2VDA3OjUxOjM2WiIsCiAgICAidmVyaWZpY2F0aW9uTWV0aG9kIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoI3o2TWtzOW05aWZMd3kzSldxSDRjNTdFYkJRVlMyU3BSQ2pmYTc5d0hiNXZXTTZ2aCIsCiAgICAiandzIjogImV5SmlOalFpT21aaGJITmxMQ0pqY21sMElqcGJJbUkyTkNKZExDSmhiR2NpT2lKRlpFUlRRU0o5Li42eFNxb1pqYTBOd2pGMGFmOVprbnF4M0NiaDlHRU51bkJmOUM4dUwydWxHZnd1czNVRk1fWm5oUGpXdEhQbC03MkU5cDNCVDVmMnB0Wm9Za3RNS3BEQSIKICB9Cn0"
}

func getNoHolderVPToken() string {
	return "ewogICJAY29udGV4dCI6IFsKICAgICJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIKICBdLAogICJ0eXBlIjogWwogICAgIlZlcmlmaWFibGVQcmVzZW50YXRpb24iCiAgXSwKICAidmVyaWZpYWJsZUNyZWRlbnRpYWwiOiBbCiAgICB7CiAgICAgICJ0eXBlcyI6IFsKICAgICAgICAiUGFja2V0RGVsaXZlcnlTZXJ2aWNlIiwKICAgICAgICAiVmVyaWZpYWJsZUNyZWRlbnRpYWwiCiAgICAgIF0sCiAgICAgICJAY29udGV4dCI6IFsKICAgICAgICAiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLAogICAgICAgICJodHRwczovL3czaWQub3JnL3NlY3VyaXR5L3N1aXRlcy9qd3MtMjAyMC92MSIKICAgICAgXSwKICAgICAgImNyZWRlbnRpYWxzU3ViamVjdCI6IHt9LAogICAgICAiYWRkaXRpb25hbFByb3AxIjoge30KICAgIH0KICBdLAogICJpZCI6ICJlYmM2ZjFjMiIsCiAgImhvbGRlciI6IHsKICAgICJub3RhIjogImhvbGRlciIKICB9LAogICJwcm9vZiI6IHsKICAgICJ0eXBlIjogIkpzb25XZWJTaWduYXR1cmUyMDIwIiwKICAgICJjcmVhdG9yIjogImRpZDprZXk6ejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJjcmVhdGVkIjogIjIwMjMtMDEtMDZUMDc6NTE6MzZaIiwKICAgICJ2ZXJpZmljYXRpb25NZXRob2QiOiAiZGlkOmtleTp6Nk1rczltOWlmTHd5M0pXcUg0YzU3RWJCUVZTMlNwUkNqZmE3OXdIYjV2V002dmgjejZNa3M5bTlpZkx3eTNKV3FINGM1N0ViQlFWUzJTcFJDamZhNzl3SGI1dldNNnZoIiwKICAgICJqd3MiOiAiZXlKaU5qUWlPbVpoYkhObExDSmpjbWwwSWpwYkltSTJOQ0pkTENKaGJHY2lPaUpGWkVSVFFTSjkuLjZ4U3FvWmphME53akYwYWY5WmtucXgzQ2JoOUdFTnVuQmY5Qzh1TDJ1bEdmd3VzM1VGTV9abmhQald0SFBsLTcyRTlwM0JUNWYycHRab1lrdE1LcERBIgogIH0KfQ"
}

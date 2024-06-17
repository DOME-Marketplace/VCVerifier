/*
 * vcverifier
 *
 * Backend component to verify credentials
 *
 * API version: 0.0.1
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package openapi

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/fiware/VCVerifier/common"
	"github.com/fiware/VCVerifier/config"
	"github.com/fiware/VCVerifier/logging"
	"github.com/fiware/VCVerifier/verifier"
	"github.com/piprate/json-gold/ld"
	"github.com/trustbloc/vc-go/verifiable"

	"github.com/gin-gonic/gin"
)

var apiVerifier verifier.Verifier
var configuration *config.Configuration
var presentationOptions []verifiable.PresentationOpt

var ErrorMessagNoGrantType = ErrorMessage{"no_grant_type_provided", "Token requests require a grant_type."}
var ErrorMessageUnsupportedGrantType = ErrorMessage{"unsupported_grant_type", "Provided grant_type is not supported by the implementation."}
var ErrorMessageNoCode = ErrorMessage{"no_code_provided", "Token requests require a code."}
var ErrorMessageNoRedircetUri = ErrorMessage{"no_redirect_uri_provided", "Token requests require a redirect_uri."}
var ErrorMessageNoState = ErrorMessage{"no_state_provided", "Authentication requires a state provided as query parameter."}
var ErrorMessageNoScope = ErrorMessage{"no_scope_provided", "Authentication requires a scope provided as a form parameter."}
var ErrorMessageNoToken = ErrorMessage{"no_token_provided", "Authentication requires a token provided as a form parameter."}
var ErrorMessageNoPresentationSubmission = ErrorMessage{"no_presentation_submission_provided", "Authentication requires a presentation submission provided as a form parameter."}
var ErrorMessageNoCallback = ErrorMessage{"no_callback_provided", "A callback address has to be provided as query-parameter."}
var ErrorMessageUnableToDecodeToken = ErrorMessage{"invalid_token", "Token could not be decoded."}
var ErrorMessageUnableToDecodeCredential = ErrorMessage{"invalid_token", "Could not read the credential(s) inside the token."}
var ErrorMessageUnableToDecodeHolder = ErrorMessage{"invalid_token", "Could not read the holder inside the token."}

func getApiVerifier() verifier.Verifier {
	if apiVerifier == nil {
		apiVerifier = verifier.GetVerifier()
	}
	return apiVerifier
}

func getConfiguration() *config.Configuration {
	if configuration == nil {
		configuration = verifier.GetConfiguration()
	}
	return configuration
}

// GetToken - Token endpoint to exchange the authorization code with the actual JWT.
func GetToken(c *gin.Context) {

	logging.Log().Debugf("%v", c.Request)
	grantType, grantTypeExists := c.GetPostForm("grant_type")
	if !grantTypeExists {
		logging.Log().Debug("No grant_type present in the request.")
		c.AbortWithStatusJSON(400, ErrorMessagNoGrantType)
		return
	}

	if grantType == common.TYPE_CODE {
		handleTokenTypeCode(c)
	} else if grantType == common.TYPE_VP_TOKEN {
		handleTokenTypeVPToken(c)
	} else {
		c.AbortWithStatusJSON(400, ErrorMessageUnsupportedGrantType)
	}
}

func handleTokenTypeVPToken(c *gin.Context) {
	var requestBody TokenRequestBody

	vpToken, vpTokenExists := c.GetPostForm("vp_token")
	if !vpTokenExists {
		logging.Log().Debug("No vp token present in the request.")
		c.AbortWithStatusJSON(400, ErrorMessageNoToken)
		return
	}

	logging.Log().Warnf("Got token %s", vpToken)

	// not used at the moment
	// presentationSubmission, presentationSubmissionExists := c.GetPostForm("presentation_submission")
	// if !presentationSubmissionExists {
	//	logging.Log().Debug("No presentation submission present in the request.")
	//	c.AbortWithStatusJSON(400, ErrorMessageNoPresentationSubmission)
	//	return
	//}

	scope, scopeExists := c.GetPostForm("scope")
	if !scopeExists {
		logging.Log().Debug("No scope present in the request.")
		c.AbortWithStatusJSON(400, ErrorMessageNoScope)
		return
	}

	presentation, err := extractVpFromToken(c, vpToken)
	if err != nil {
		logging.Log().Warnf("Was not able to extract the credentials from the vp_token.")
		return
	}
	clientId := c.GetHeader("client_id")

	scopes := strings.Split(scope, ",")

	// Subject is empty since multiple VCs with different subjects can be provided
	expiration, signedToken, err := getApiVerifier().GenerateToken(clientId, "", clientId, scopes, presentation)
	if err != nil {
		logging.Log().Error("Failure during generating M2M token: ", err)
		c.AbortWithStatusJSON(400, err)
		return
	}
	response := TokenResponse{"Bearer", float32(expiration), signedToken, requestBody.Scope, ""}
	logging.Log().Infof("Generated and signed token: %v", response)
	c.JSON(http.StatusOK, response)
}

func handleTokenTypeCode(c *gin.Context) {

	code, codeExists := c.GetPostForm("code")
	if !codeExists {
		logging.Log().Debug("No code present in the request.")
		c.AbortWithStatusJSON(400, ErrorMessageNoCode)
		return
	}

	redirectUri, redirectUriExists := c.GetPostForm("redirect_uri")
	if !redirectUriExists {
		logging.Log().Debug("No redircet_uri present in the request.")
		c.AbortWithStatusJSON(400, ErrorMessageNoRedircetUri)
		return
	}
	jwt, expiration, err := getApiVerifier().GetToken(code, redirectUri)

	if err != nil {
		c.AbortWithStatusJSON(403, ErrorMessage{Summary: err.Error()})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{TokenType: "Bearer", ExpiresIn: float32(expiration), AccessToken: jwt})
}

// StartSIOPSameDevice - Starts the siop flow for credentials hold by the same device
func StartSIOPSameDevice(c *gin.Context) {
	state, stateExists := c.GetQuery("state")
	if !stateExists {
		logging.Log().Debugf("No state was provided.")
		c.AbortWithStatusJSON(400, ErrorMessage{"no_state_provided", "Authentication requires a state provided as query parameter."})
		return
	}
	redirectPath, redirectPathExists := c.GetQuery("redirect_path")
	if !redirectPathExists {
		redirectPath = "/"
	}

	protocol := "https"
	if c.Request.TLS == nil {
		protocol = "http"
	}

	clientId, clientIdExists := c.GetQuery("client_id")
	if !clientIdExists {
		logging.Log().Infof("Start a login flow for a not specified client.")
	}

	redirect, err := getApiVerifier().StartSameDeviceFlow(c.Request.Host, protocol, state, redirectPath, clientId)
	if err != nil {
		logging.Log().Warnf("Error starting the same-device flow. Err: %v", err)
		c.AbortWithStatusJSON(500, ErrorMessage{err.Error(), "Was not able to start the same device flow."})
		return
	}
	c.Redirect(302, redirect)
}

// VerifierAPIAuthenticationResponse - Stores the credential for the given session
func VerifierAPIAuthenticationResponse(c *gin.Context) {
	var state string
	stateForm, stateFormExists := c.GetPostForm("state")
	stateQuery, stateQueryExists := c.GetQuery("state")
	if !stateFormExists && !stateQueryExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoState)
		return
	}
	if stateFormExists {
		state = stateForm
	} else {
		// allow the state submitted through a query parameter for backwards-compatibility
		state = stateQuery
	}

	vptoken, tokenExists := c.GetPostForm("vp_token")
	if !tokenExists {
		logging.Log().Info("No token was provided.")
		c.AbortWithStatusJSON(400, ErrorMessageNoToken)
		return
	}

	presentation, err := extractVpFromToken(c, vptoken)
	if err != nil {
		logging.Log().Warnf("Was not able to extract the presentation from the vp_token.")
		return
	}
	handleAuthenticationResponse(c, state, presentation)
}

// GetVerifierAPIAuthenticationResponse - Stores the credential for the given session
func GetVerifierAPIAuthenticationResponse(c *gin.Context) {
	state, stateExists := c.GetQuery("state")
	if !stateExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoState)
		return
	}
	vpToken, tokenExists := c.GetQuery("vp_token")
	if !tokenExists {
		logging.Log().Info("No token was provided.")
		c.AbortWithStatusJSON(400, ErrorMessageNoToken)
		return
	}
	presentation, err := extractVpFromToken(c, vpToken)
	if err != nil {
		logging.Log().Warnf("Was not able to extract the presentation from the vp_token.")
		return
	}
	handleAuthenticationResponse(c, state, presentation)
}

func extractVpFromToken(c *gin.Context, vpToken string) (parsedPresentation *verifiable.Presentation, err error) {

	tokenBytes, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		logging.Log().Infof("Was not able to decode the form string %s. Err: %v", vpToken, err)
		c.AbortWithStatusJSON(400, ErrorMessageUnableToDecodeToken)
		return
	}

	// takes care of the verification
	parsedPresentation, err = verifiable.ParsePresentation(tokenBytes,
		getPresentationOpts()...)
	if err != nil {
		logging.Log().Infof("Was not able to parse the token %s. Err: %v", vpToken, err)
		c.AbortWithStatusJSON(400, ErrorMessageUnableToDecodeToken)
		return
	}
	return
}

func handleAuthenticationResponse(c *gin.Context, state string, presentation *verifiable.Presentation) {

	sameDeviceResponse, err := getApiVerifier().AuthenticationResponse(state, presentation)
	if err != nil {
		logging.Log().Warnf("Was not able to fullfil the authentication response. Err: %v", err)
		c.AbortWithStatusJSON(400, ErrorMessage{Summary: err.Error()})
		return
	}
	if sameDeviceResponse != (verifier.SameDeviceResponse{}) {
		c.Redirect(302, fmt.Sprintf("%s?state=%s&code=%s", sameDeviceResponse.RedirectTarget, sameDeviceResponse.SessionId, sameDeviceResponse.Code))
		return
	}
	logging.Log().Debugf("Successfully authenticated %s.", state)
	c.JSON(http.StatusOK, gin.H{})
}

// VerifierAPIJWKS - Provides the public keys for the given verifier, to be used for verifing the JWTs
func VerifierAPIJWKS(c *gin.Context) {
	c.JSON(http.StatusOK, getApiVerifier().GetJWKS())
}

// VerifierAPIOpenID
func VerifierAPIOpenIDConfiguration(c *gin.Context) {

	metadata, err := getApiVerifier().GetOpenIDConfiguration(c.Param("serviceIdentifier"))
	if err != nil {
		c.AbortWithStatusJSON(500, ErrorMessage{err.Error(), "Was not able to generate the OpenID metadata."})
		return
	}
	c.JSON(http.StatusOK, metadata)
}

// VerifierAPIStartSIOP - Initiates the siop flow and returns the 'openid://...' connection string
func VerifierAPIStartSIOP(c *gin.Context) {
	state, stateExists := c.GetQuery("state")
	if !stateExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoState)
		// early exit
		return
	}

	callback, callbackExists := c.GetQuery("client_callback")
	if !callbackExists {
		c.AbortWithStatusJSON(400, ErrorMessageNoCallback)
		// early exit
		return
	}
	protocol := "https"
	if c.Request.TLS == nil {
		protocol = "http"
	}
	clientId, clientIdExists := c.GetQuery("client_id")
	if !clientIdExists {
		logging.Log().Infof("Start a login flow for a not specified client.")
	}

	connectionString, err := getApiVerifier().StartSiopFlow(c.Request.Host, protocol, callback, state, clientId)
	if err != nil {
		c.AbortWithStatusJSON(500, ErrorMessage{err.Error(), "Was not able to generate the connection string."})
		return
	}
	c.String(http.StatusOK, connectionString)
}

func getPresentationOpts() []verifiable.PresentationOpt {
	if len(presentationOptions) > 0 {
		return presentationOptions
	}

	fingerprint := ""
	if getConfiguration() == nil {
		logging.Log().Warn("No configuration available.")
	} else {
		fingerprint = getConfiguration().Verifier.CertificateFingerprint
	}

	return []verifiable.PresentationOpt{
		verifiable.WithPresProofChecker(verifier.NewDomeJWTProofChecker(fingerprint)),
		verifiable.WithPresJSONLDDocumentLoader(ld.NewDefaultDocumentLoader(http.DefaultClient))}
}

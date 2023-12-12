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
	"net/http"

	"github.com/fiware/VCVerifier/config"
	"github.com/gin-gonic/gin"
)

// Route is the information for every URI.
type Route struct {
	// Name is the name of this Route.
	Name string
	// Method is the string for the HTTP method. ex) GET, POST etc..
	Method string
	// Pattern is the pattern of the URI.
	Pattern string
	// HandlerFunc is the handler function of this route.
	HandlerFunc gin.HandlerFunc
}

// Routes is the list of the generated Route.
type Routes []Route

var configuration config.Server

// NewRouter returns a new router.
func NewRouter(serverConfig config.Server) *gin.Engine {
	router := gin.New()

	configuration = serverConfig

	for _, route := range routes {
		switch route.Method {
		case http.MethodGet:
			router.GET(route.Pattern, route.HandlerFunc)
		case http.MethodPost:
			router.POST(route.Pattern, route.HandlerFunc)
		case http.MethodPut:
			router.PUT(route.Pattern, route.HandlerFunc)
		case http.MethodPatch:
			router.PATCH(route.Pattern, route.HandlerFunc)
		case http.MethodDelete:
			router.DELETE(route.Pattern, route.HandlerFunc)
		}
	}

	return router
}

// Index is the index handler.
func Index(c *gin.Context) {
	c.String(http.StatusOK, "Hello World!")
}

var routes = Routes{

	{
		"GetToken",
		http.MethodPost,
		"/token",
		GetToken,
	},

	{
		"StartSIOPSameDevice",
		http.MethodGet,
		"/api/v1/samedevice",
		StartSIOPSameDevice,
	},

	{
		"VerifierAPIAuthenticationResponse",
		http.MethodPost,
		"/api/v1/authentication_response",
		VerifierAPIAuthenticationResponse,
	},

	{
		"GetVerifierAPIAuthenticationResponse",
		http.MethodGet,
		"/api/v1/authentication_response",
		GetVerifierAPIAuthenticationResponse,
	},

	{
		"VerifierAPIJWKS",
		http.MethodGet,
		"/.well-known/jwks",
		VerifierAPIJWKS,
	},

	{
		"VerifierAPIOpenIDConfiguration",
		http.MethodGet,
		"/services/:serviceIdentifier/.well-known/openid-configuration",
		VerifierAPIOpenIDConfiguration,
	},

	{
		"VerifierAPIStartSIOP",
		http.MethodGet,
		"/api/v1/startsiop",
		VerifierAPIStartSIOP,
	},

	{
		"VerifierPageDisplayQRSIOP",
		http.MethodGet,
		"/api/v1/loginQR",
		VerifierPageDisplayQRSIOP,
	},
}

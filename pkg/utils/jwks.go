package utils

import (
	"os"
	"time"

	"github.com/MicahParks/keyfunc"
)

var (
	Jwks *keyfunc.JWKS
)

func InitJWKS() {
	Logger.Info("Init Keycloak config")
	jwksURL := os.Getenv("KEYCLOAK_CERT_URL")

	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			LogIfError("There was an error with the jwt.Keyfunc", err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	// Create the JWKS from the resource at the given URL.
	err := error(nil)
	Jwks, err = keyfunc.Get(jwksURL, options)
	LogIfPanic("Failed to create JWKS from resource at the given URL.", err)
	Logger.Info("Finished Keycloak config")
}

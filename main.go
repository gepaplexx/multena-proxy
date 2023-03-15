package main

import (
	"crypto/tls"
	"fmt"
	"github.com/gepaplexx/multena-proxy/pkg/labels_provider"
	"github.com/gepaplexx/multena-proxy/pkg/model"
	"github.com/gepaplexx/multena-proxy/pkg/rewrite"
	"github.com/gepaplexx/multena-proxy/pkg/utils"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"io"
	"net/http"
	_ "net/http/pprof"
	"net/url"
)

func init() {
	utils.InitViper()
	utils.InitLogging()
	utils.Logger.Info("Init Proxy")
	utils.Logger.Info("Set http client to ignore self signed certificates")
	utils.Logger.Info("Config ", zap.Any("cfg", utils.C))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	utils.InitJWKS()
	utils.InitKubeClient()
	utils.InitDB()
	utils.Logger.Info("Init Complete")
}

func main() {
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()
		if err != nil {
			fmt.Println("Error syncing logger", err)
			panic(err)
		}
	}(utils.Logger)

	utils.Logger.Info("Starting Proxy")
	// define origin server URLs
	originServerURL, err := url.Parse(utils.C.Proxy.UpstreamURL)
	utils.LogIfPanic("originServerURL must be set", err)
	utils.Logger.Debug("Upstream URL", zap.String("url", originServerURL.String()))

	originBypassServerURL, err := url.Parse(utils.C.Proxy.UpstreamBypassURL)
	utils.LogIfPanic("OriginBypassServerURL must be set", err)
	utils.Logger.Debug("Bypass Upstream URL", zap.String("url", originBypassServerURL.String()))

	utils.Logger.Debug("Tenant Label", zap.String("label", utils.C.Proxy.TenantLabel))
	utils.Logger.Debug("TokenExchangeURL", zap.String("label", utils.C.TokenExchange.URL))

	reverseProxy := configureProxy(originBypassServerURL, utils.C.Proxy.TenantLabel, originServerURL, utils.C.TokenExchange.URL)

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(healthz))
	mux.Handle("/", reverseProxy)
	go func() {
		err := http.ListenAndServe("localhost:6060", nil)
		utils.LogIfError("Error while serving pprof", err)
		defer utils.CloseDB()
	}()
	utils.LogIfPanic("error while serving", http.ListenAndServe(":8080", mux))

}

func healthz(w http.ResponseWriter, _ *http.Request) {
	utils.Logger.Debug("Healthz")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Ok")
	return
}

func configureProxy(originBypassServerURL *url.URL, tenantLabel string, originServerURL *url.URL, tokenExchangeURL string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		utils.Logger.Info("Recived request", zap.Any("request", req))

		if req.Header.Get("Authorization") == "" {
			utils.Logger.Warn("No Authorization header found")
			rw.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(rw, "No Authorization header found")
			return
		}

		//parse jwt from request
		tokenString := string(req.Header.Get("Authorization"))[7:]
		var keycloakToken model.KeycloakToken
		token, err := jwt.ParseWithClaims(tokenString, &keycloakToken, utils.Jwks.Keyfunc)
		//if token invalid or expired, return 401

		utils.LogIfError("Token Parsing error", err)
		if !token.Valid && !utils.C.Dev.Enabled {
			rw.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(rw, "error while parsing token")
			utils.Logger.Warn("Invalid token", zap.Any("token", token))
			return
		}

		//if user in admin group
		if utils.Contains(keycloakToken.Groups, utils.C.Proxy.AdminGroup) || utils.Contains(keycloakToken.ApaGroupsOrg, utils.C.Proxy.AdminGroup) {
			req.Host = originBypassServerURL.Host
			req.URL.Host = originBypassServerURL.Host
			req.URL.Scheme = originBypassServerURL.Scheme
			req.Header.Set("Authorization", "Bearer "+utils.ServiceAccountToken)
		} else {
			var labels []string
			switch provider := utils.C.Proxy.Provider; provider {
			case "rolebinding":
				labels = labels_provider.GetLabelsFromRoleBindings(keycloakToken.PreferredUsername)
			case "mysql":
				labels = labels_provider.GetLabelsFromDB(keycloakToken.Email)
			case "configmap":
				labels = labels_provider.GetLabelsCM(keycloakToken.PreferredUsername)
			default:
				utils.Logger.Panic("No provider set")
			}
			utils.Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername))
			utils.Logger.Debug("Labels", zap.Any("labels", labels))
			URL := req.URL.String()
			req.URL, err = url.Parse(rewrite.UrlRewriter(URL, labels, tenantLabel))
			utils.LogIfError("Error while parsing url", err)

			//proxy request to origin server
			req.Host = originServerURL.Host
			req.URL.Host = originServerURL.Host
			req.URL.Scheme = originServerURL.Scheme
			req.Header.Set("Authorization", "Bearer "+utils.ServiceAccountToken)
		}

		//clear request URI
		utils.Logger.Debug("Client request", zap.Any("request", req))
		req.RequestURI = ""
		originServerResponse, err := http.DefaultClient.Do(req)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(rw, err)
			utils.LogIfError("Client request error", err)
			return
		}

		originBody, err := io.ReadAll(originServerResponse.Body)
		utils.LogIfError("Error reading origin server response body", err)
		utils.Logger.Debug("Upstream Response", zap.Any("response", originServerResponse), zap.Any("body", originBody))

		// return response to the client
		rw.WriteHeader(http.StatusOK)
		_, err = rw.Write(originBody)
		utils.LogIfError("Error writing response to client", err)

		utils.Logger.Debug("Finished Client request")

		defer func(Body io.ReadCloser) {
			err := Body.Close()
			utils.LogIfError("Error closing body", err)
		}(originServerResponse.Body)
	}
}

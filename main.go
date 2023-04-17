package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	logqlv2 "github.com/gepaplexx/multena-proxy/logql/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/prometheus/prometheus/model/labels"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
)

func main() {
	doInit()
	defer func(Logger *zap.Logger) {
		err := Logger.Sync()

		if err != nil {
			fmt.Println("Error syncing logger", err)
			panic(err)
		}
	}(Logger)

	Logger.Info("Starting Proxy")

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(healthz))
	mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
	mux.Handle("/", http.HandlerFunc(reverseProxy))
	err := http.ListenAndServe(fmt.Sprintf(":%d", C.Proxy.Port), mux)
	if err != nil {
		Logger.Panic("Error while serving", zap.Error(err))
	}
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	Logger.Debug("Healthz")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Ok")
	return
}

func reverseProxy(rw http.ResponseWriter, req *http.Request) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	dump, err := httputil.DumpRequest(req, true)
	Logger.Debug("Request", zap.String("request", fmt.Sprintf("%s", dump)), zap.Int("line", 50))
	if req.Header.Get("Authorization") == "" {
		Logger.Warn("No Authorization header found", zap.Int("line", 52))
		rw.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(rw, "No Authorization header found")
		return
	}

	//parse jwt from request
	if len(req.Header.Get("Authorization")) < 7 {
		rw.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(rw, "error while parsing token")
		return
	}
	tokenString := req.Header.Get("Authorization")[7:]
	keycloakToken := KeycloakToken{}
	token, err := jwt.ParseWithClaims(tokenString, &keycloakToken, Jwks.Keyfunc)
	if err != nil {
		Logger.Error("Error parsing Keycloak token", zap.Error(err), zap.Int("line", 68))
		_, _ = fmt.Fprint(rw, "Error parsing Keycloak token")
		return
	}

	//if token invalid or expired, return 401
	if !token.Valid && !C.Dev.Enabled {
		rw.WriteHeader(http.StatusForbidden)
		Logger.Debug("Invalid token", zap.Any("token", token), zap.Int("line", 76))
		_, _ = fmt.Fprint(rw, "error while parsing token")
		return
	}

	//if user in admin group
	var upstreamUrl *url.URL
	if ContainsIgnoreCase(keycloakToken.Groups, C.Proxy.AdminGroup) || ContainsIgnoreCase(keycloakToken.ApaGroupsOrg, C.Proxy.AdminGroup) {
		upstreamUrl, err = url.Parse(C.Proxy.UpstreamBypassURL)
		if err != nil {
			Logger.Error("Error parsing upstream url", zap.Error(err), zap.Int("line", 86))
			_, _ = fmt.Fprint(rw, "Error parsing upstream url")
			return
		}
	} else {
		var tenantLabels []string
		switch provider := C.Proxy.Provider; provider {
		case "project":
			tenantLabels = GetLabelsFromProject(keycloakToken.PreferredUsername)
		case "mysql":
			tenantLabels = GetLabelsFromDB(keycloakToken.Email)
		case "configmap":
			tenantLabels = GetLabelsCM(keycloakToken.PreferredUsername, keycloakToken.Groups)
		default:
			Logger.Error("No provider set", zap.Int("line", 100))
			_, _ = fmt.Fprint(rw, "Internal Server Error")
			return
		}

		Logger.Debug("username", zap.String("username", keycloakToken.PreferredUsername), zap.Int("line", 105))
		Logger.Debug("Labels", zap.Any("tenantLabels", tenantLabels), zap.Int("line", 106))

		if req.Header.Get("X-Plugin-Id") == "loki" || req.URL.Path[:13] == "/loki/api/v1/" {
			upstreamUrl, err = url.Parse(C.Proxy.UpstreamURLLoki)
			if err != nil {
				Logger.Error("Error parsing upstream url", zap.Error(err), zap.Int("line", 111))
				_, _ = fmt.Fprint(rw, "Internal Server Error")
				return
			}
			query := req.URL.Query().Get("query")
			if query == "" {
				query = "{__name__=~\".+\"}"
			}

			Logger.Debug("query", zap.String("query", query), zap.Int("line", 120))

			lm := []*labels.Matcher{}
			for _, tl := range tenantLabels {
				lm = append(lm, &labels.Matcher{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: tl,
				})
			}
			// Fix label matchers to include a non nil FastRegexMatcher for regex types.
			for i, m := range lm {
				nm, err := labels.NewMatcher(m.Type, m.Name, m.Value)
				if err != nil {
					rw.WriteHeader(http.StatusForbidden)
					Logger.Error("failed parsing label matcher", zap.Error(err), zap.Int("line", 134))
					_, _ = fmt.Fprint(rw, "failed parsing label matcher")
					return
				}

				lm[i] = nm
			}

			expr, err := logqlv2.ParseExpr(query)
			if err != nil {
				rw.WriteHeader(http.StatusForbidden)
				Logger.Error("failed parsing LogQL expression", zap.Error(err), zap.Int("line", 144))
				_, _ = fmt.Fprint(rw, "failed parsing LogQL expression")
				return
			}

			expr.Walk(func(expr interface{}) {
				switch le := expr.(type) {
				case *logqlv2.StreamMatcherExpr:
					if le.Matchers() == nil {
						le.SetMatchers(lm)
					} else {
						err := checkItemsInList(le.Matchers(), lm)
						if err != nil {
							rw.WriteHeader(http.StatusForbidden)
							Logger.Error("Unauthorized label", zap.Error(err), zap.Int("line", 154))
							_, _ = fmt.Fprint(rw, "Unauthorized label")
							return
						}
					}
				default:
					// Do nothing
				}
			})

			q := req.URL.Query()
			q.Set("query", expr.String())
			req.URL.RawQuery = q.Encode()

		} else {
			URL := req.URL.String()
			req.URL, err = url.Parse(UrlRewriter(URL, tenantLabels, C.Proxy.TenantLabel))
			if err != nil {
				rw.WriteHeader(http.StatusForbidden)
				Logger.Error("Error parsing rewritten url", zap.Error(err), zap.Int("line", 174))
				_, _ = fmt.Fprint(rw, "Error parsing rewritten url")
				return
			}

			//proxy request to origin server
			upstreamUrl, err = url.Parse(C.Proxy.UpstreamURL)
			if err != nil {
				rw.WriteHeader(http.StatusForbidden)
				Logger.Error("Error parsing upstream url", zap.Error(err))
				_, _ = fmt.Fprint(rw, "Error parsing upstream url")
				return
			}
		}

	}

	req.Host = upstreamUrl.Host
	req.URL.Host = upstreamUrl.Host
	req.URL.Scheme = upstreamUrl.Scheme

	req.Header.Set("Authorization", "Bearer "+ServiceAccountToken)

	Logger.Debug("Query", zap.String("query", req.URL.String()), zap.Int("line", 196))

	//clear request URI
	dump, err = httputil.DumpRequest(req, true)
	Logger.Debug("Client request", zap.String("request", fmt.Sprintf("%s", dump)), zap.Int("line", 200))
	req.RequestURI = ""
	originServerResponse, err := http.DefaultClient.Do(req)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(rw, err)
		if err != nil {
			Logger.Error("Error making request to origin", zap.Error(err), zap.Int("line", 207))
		}
		return
	}

	originBody, err := io.ReadAll(originServerResponse.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		Logger.Error("Error reading origin response", zap.Error(err), zap.Int("line", 214))
		_, _ = fmt.Fprint(rw, "Error reading origin response")
		return
	}

	//originServerResponseDump, err := httputil.DumpResponse(originServerResponse, true)
	Logger.Debug("Upstream Response", zap.Any("header", originServerResponse.Header), zap.String("body", fmt.Sprintf("%s", originBody)), zap.Int("line", 220))

	// return response to the client
	rw.WriteHeader(http.StatusOK)
	_, err = rw.Write(originBody)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		Logger.Error("Error writing origin response to client", zap.Error(err), zap.Int("line", 226))
		_, _ = fmt.Fprint(rw, "Error writing origin response to client")
		return
	}

	Logger.Debug("Finished Client request", zap.Int("line", 231))
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			Logger.Error("Error closing body", zap.Error(err), zap.Int("line", 235))
			_, _ = fmt.Fprint(rw, "Error closing body")
			return
		}
	}(originServerResponse.Body)
}

func checkItemsInList(queryMatchers, authzMatchers []*labels.Matcher) error {
	for _, item := range queryMatchers {
		if !containsMatcher(authzMatchers, item) {
			return errors.New("Unauthorized label")
		}
	}
	return nil
}

func containsMatcher(list []*labels.Matcher, item *labels.Matcher) bool {
	for _, i := range list {
		if i.Value == item.Value {
			return true
		}
	}
	return false
}

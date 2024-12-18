package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetActorHeaderLogQL(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Loki: LokiConfig{
				ActorHeader: "X-Actor",
			},
		},
	}
	token := OAuthToken{
		PreferredUsername: "user",
		Email:             "user@example.com",
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := setActorHeaderLogQL(req, token, app)
	assert.NoError(t, err)
	assert.Equal(t, "dXNlcnVzZXJAZXhhbXBsZS5jb20=", req.Header.Get("X-Actor"))
	fmt.Println(req.Header)
}

func TestSetActorHeaderPromQL(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Thanos: ThanosConfig{
				ActorHeader: "X-Actor",
			},
		},
	}
	token := OAuthToken{
		PreferredUsername: "user",
		Email:             "user@example.com",
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	err := setActorHeaderPromQL(req, token, app)
	assert.NoError(t, err)
	assert.Equal(t, "dXNlcnVzZXJAZXhhbXBsZS5jb20=", req.Header.Get("X-Actor"))
}

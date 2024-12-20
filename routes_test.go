package main

import (
	"fmt"
	"io"
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

func TestWithHealthz(t *testing.T) {
	app := &App{
		Cfg: &Config{
			Alert: AlertConfig{
				Enabled: false,
			},
		},
	}

	app = app.WithHealthz()

	ts := httptest.NewServer(app.i)
	defer ts.Close()

	t.Run("Healthz OK", func(t *testing.T) {
		app.healthy = true
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("Failed to send GET request: %v", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}
	})

	t.Run("Healthz Not OK", func(t *testing.T) {
		app.healthy = false
		resp, err := http.Get(ts.URL + "/healthz")
		if err != nil {
			t.Fatalf("Failed to send GET request: %v", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}(resp.Body)

		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, resp.StatusCode)
		}
	})

	t.Run("Metrics endpoint", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/metrics")
		if err != nil {
			t.Fatalf("Failed to send GET request: %v", err)
		}
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				t.Fatalf("Failed to close response body: %v", err)
			}
		}(resp.Body)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, resp.StatusCode)
		}
	})
}

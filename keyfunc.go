package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/MicahParks/keyfunc/v3"

	"github.com/MicahParks/jwkset"
)

var (
	// ErrKeyfunc is returned when a keyfunc error occurs.
	ErrKeyfunc = errors.New("failed keyfunc")
)

func NewCombinedJwks(ctx context.Context, urls []string, raw json.RawMessage) (keyfunc.Keyfunc, error) {
	client, err := jwkset.NewDefaultHTTPClientCtx(ctx, urls)
	if err != nil {
		return nil, err
	}

	if raw != nil {
		var jwks jwkset.JWKSMarshal
		err := json.Unmarshal(raw, &jwks)
		if err != nil {
			return nil, fmt.Errorf("%w: could not unmarshal raw JWK Set JSON", errors.Join(err, ErrKeyfunc))
		}
		jwkss, err := jwks.JWKSlice()
		if err != nil {
			return nil, fmt.Errorf("failed to create a slice of JWK from JWKSMarshal: %w", err)
		}
		for _, jwk := range jwkss {
			err = client.KeyWrite(context.Background(), jwk)
			if err != nil {
				return nil, fmt.Errorf("failed to write JWK to storage: %w", err)
			}
		}
	}

	options := keyfunc.Options{
		Storage: client,
	}
	return keyfunc.New(options)
}

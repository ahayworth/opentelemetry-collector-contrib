// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oidcauthextension

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDuplicateIssuers(t *testing.T) {
	config := &Config{
		Attribute: "authorization",
		Providers: []ProviderCfg{
			{
				IssuerURL: "https://example.com",
				Audience:  "https://example.com",
			},
			{
				IssuerURL: "https://example.com",
				Audience:  "https://example.com",
			},
		},
	}
	require.Error(t, config.Validate())
}

func TestInvalidPublicKeys(t *testing.T) {
	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	config := &Config{
		Providers: []ProviderCfg{
			{
				IssuerURL:  "https://example.com",
				Audience:   "https://example.com",
				PublicKeys: []crypto.PublicKey{privKey.Public()},
			},
		},
	}
	require.Error(t, config.Validate())
}

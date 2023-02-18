// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"net/http"

	"github.com/spf13/viper"
)

type ebsiTrustList struct {
	hasBaseUrl     string
	hasAuthToken   string
	hasConformance string
	hasVerbose     bool
	hasHttpClient  *http.Client
}

type trustListOption func(*ebsiTrustList)

// defaultOptions sets the default options
func defaultOptions() *ebsiTrustList {
	viper.SetEnvPrefix("ebsi") // will be uppercased automatically
	viper.BindEnv("BaseUrl")
	viper.BindEnv("Verbose")
	// Other api environments must be set with the env variable
	// f.e. set EBSI_BASEURL=https://api.preprod.ebsi.eu
	viper.SetDefault("BaseUrl", "https://api-pilot.ebsi.eu")
	//viper.SetDefault("BaseUrl", "https://api.test.intebsi.xyz")
	viper.SetDefault("Verbose", false)
	viper.SetDefault("Conformance", "")

	return &ebsiTrustList{
		hasBaseUrl:     viper.GetString("BaseUrl"),
		hasVerbose:     viper.GetBool("Verbose"),
		hasConformance: viper.GetString("Conformance"),
		hasHttpClient:  http.DefaultClient,
	}
}

// WithHttpClient sets the option of the http client
func WithHttpClient(httpClient *http.Client) trustListOption {
	return func(e *ebsiTrustList) {
		e.hasHttpClient = httpClient
	}
}

// WithAuthToken sets the option of access token
func WithAuthToken(authToken string) trustListOption {
	return func(e *ebsiTrustList) {
		e.hasAuthToken = authToken
	}
}

// WithBaseUrl sets the option of base url of the vdr
func WithBaseUrl(baseUrl string) trustListOption {
	return func(e *ebsiTrustList) {
		e.hasBaseUrl = baseUrl
	}
}

// WithVerbose is used for debugging the requests
func WithVerbose(verbose bool) trustListOption {
	return func(e *ebsiTrustList) {
		e.hasVerbose = verbose
	}
}

func NewEBSITrustList(options ...trustListOption) *ebsiTrustList {
	ebsi := defaultOptions()
	for _, opt := range options {
		opt(ebsi)
	}
	return ebsi
}

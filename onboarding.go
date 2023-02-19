// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type usersOnboardingResponse struct {
	Scope        string `schema:"scope"`
	ResponseType string `schema:"response_type"`
	ClientId     string `schema:"client_id"`
	Nonce        string `schema:"nonce,omitempty"`
	Request      string `request:"nonce,omitempty"`
}

// Onboard onboards a user on ebsi to start a did siop authentication request
// See https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/Users+Onboarding+API
// The user needs to provide the access token from the EU Login or from the CAPTCHA challenge
func (e *ebsiTrustList) Onboard(did string, jwkKey jwk.Key) (interface{}, error) {
	if strings.TrimSpace(did) == "" {
		return nil, errors.New("invalid_did")
	}
	if jwkKey == nil {
		return nil, errors.New("invalid_jwk")
	}

	usersOnboarding, err := e.postAuthorizationRequest()
	if err != nil {
		return nil, err
	}
	// create id token
	publicSigKey, err := jwkKey.PublicKey()
	if err != nil {
		return nil, err
	}
	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	clientId, _ := url.QueryUnescape(usersOnboarding.ClientId)
	idToken, err := jwt.NewBuilder().
		Issuer("https://self-issued.me/v2").
		Audience([]string{clientId}).
		Subject(base64.URLEncoding.EncodeToString(thumbprint)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute*5)).
		Claim("nonce", usersOnboarding.Nonce).
		Claim("sub_jwk", publicSigKey).
		Claim("responseMode", "form_post").
		Build()
	if err != nil {
		return nil, err
	}
	serialized, err := jwt.Sign(idToken, jwt.WithKey(jwa.ES256K, jwkKey))
	if err != nil {
		return nil, err
	}
	credential, err := e.postAuthenticationResponse(serialized)
	if err != nil {
		return nil, err
	}
	return credential, nil
}

// postAuthorizationRequest starts the authorization request with ebsi to onboard a user
func (e *ebsiTrustList) postAuthorizationRequest() (usersOnboardingResponse, error) {
	var (
		onboardResponse usersOnboardingResponse
	)
	// set the scope of the authorization request
	response := map[string]interface{}{}
	err := e.httpPost("/users-onboarding/v2/authentication-requests", `{"scope":"ebsi users onboarding"}`, &response)
	if err != nil {
		return onboardResponse, err
	}
	// parse the params from the authentication request
	paramsRaw := strings.SplitAfter(response["session_token"].(string), "openid://?")
	params := strings.Split(paramsRaw[1], "&")
	var sessionParams map[string][]string = map[string][]string{}
	for _, p := range params {
		keyValue := strings.Split(p, "=")
		sessionParams[keyValue[0]] = []string{keyValue[1]}
	}
	decoder := schema.NewDecoder()
	err = decoder.Decode(&onboardResponse, sessionParams)
	if err != nil {
		return onboardResponse, err
	}
	return onboardResponse, nil
}

func (e *ebsiTrustList) postAuthenticationResponse(idToken []byte) (interface{}, error) {
	response := map[string]interface{}{}
	// expect not an error on method allowed
	if err := e.httpPost("/users-onboarding/v2/authentication-responses", fmt.Sprintf(`{"id_token":"%s"}`, string(idToken)), &response); err != nil {
		return nil, err
	}
	verifiableCredential := response["verifiableCredential"]
	return verifiableCredential, nil
}

// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gossif/ebsi"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnboarding(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful": testSuccesfulOnboarding,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testSuccesfulOnboarding(t *testing.T) {
	var jwkKeyString string = `{"crv":"secp256k1","d":"98eTnvH6El3f_noCBl9tbxfWqio4VXRw5BwgiK6nL_w","kid":"did:ebsi:zwkkxMemYcj9nq1XsqT6SVG#c565a5ade5b84ba482f83be33ee94aaa","kty":"EC","x":"T0RyJUbgufnlkLmWNAsGTQ-PdpBwvtWx3Ne9b7kKI00","y":"FAgtmF3AMBTNyv-pD2ktQhUhG95mkKIrOP2FcUJi5U0"}`

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users-onboarding/v2/authentication-requests":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"session_token": "openid://?response_type=id_token&client_id=https%3A%2F%2Fapi-pilot.ebsi.eu%2Fusers-onboarding%2Fv2%2Fauthentication-responses&scope=openid+did_authn&nonce=85bf9da3-b765-4621-9ca7-f9e25e470d6b&request=eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJodHRwczovL2FwaS1waWxvdC5lYnNpLmV1L3RydXN0ZWQtYXBwcy1yZWdpc3RyeS92My9hcHBzL3VzZXJzLW9uYm9hcmRpbmctYXBpX3BpbG90LXRlbXAtMDEifQ.eyJzY29wZSI6Im9wZW5pZCBkaWRfYXV0aG4iLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoicG9zdCIsImNsaWVudF9pZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdXNlcnMtb25ib2FyZGluZy92Mi9hdXRoZW50aWNhdGlvbi1yZXNwb25zZXMiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2FwaS1waWxvdC5lYnNpLmV1L3VzZXJzLW9uYm9hcmRpbmcvdjIvYXV0aGVudGljYXRpb24tcmVzcG9uc2VzIiwibm9uY2UiOiI4NWJmOWRhMy1iNzY1LTQ2MjEtOWNhNy1mOWUyNWU0NzBkNmIiLCJpYXQiOjE2NzY4NzY4MzUsImlzcyI6InVzZXJzLW9uYm9hcmRpbmctYXBpX3BpbG90LXRlbXAtMDEiLCJleHAiOjE2NzY4NzcxMzV9.hW9lVyjtPTNi37DNse-wETR3HRJhFHVCogNHnXwZ-leUusPXvWeNVVVMFuSNvM_ZPPPGlkXpeXxuZJ8YDxwhhw"}`))

		case "/users-onboarding/v2/authentication-responses":
			result := map[string]interface{}{}
			err := json.NewDecoder(r.Body).Decode(&result)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer r.Body.Close()

			idToken, idTokenOkk := result["id_token"].(string)
			require.True(t, idTokenOkk)
			token, err := jwt.Parse([]byte(idToken), jwt.WithValidate(false), jwt.WithVerify(false))
			require.NoError(t, err)
			nonce, nonceOk := token.Get("nonce")
			require.True(t, nonceOk)
			assert.EqualValues(t, "85bf9da3-b765-4621-9ca7-f9e25e470d6b", nonce)

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"verifiableCredential":"eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJqdGkiOiJ2YzplYnNpOmF1dGhlbnRpY2F0aW9uI2I3NWY1ZDJkLWE0ZWMtNGQ1Zi1hODY0LWMyODI1MzE4YjY5YSIsInN1YiI6ImRpZDplYnNpOnp3a2t4TWVtWWNqOW5xMVhzcVQ2U1ZHIiwiaXNzIjoiZGlkOmVic2k6enIycldESEhyVUNkWkFXN3dzU2I1blEiLCJuYmYiOjE2NzY4NzY4MzUsImV4cCI6MTY5MjYwMTYzNSwiaWF0IjoxNjc2ODc2ODM1LCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6InZjOmVic2k6YXV0aGVudGljYXRpb24jYjc1ZjVkMmQtYTRlYy00ZDVmLWE4NjQtYzI4MjUzMThiNjlhIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdXRob3Jpc2F0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnpyMnJXREhIclVDZFpBVzd3c1NiNW5RIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMi0yMFQwNzowNzoxNVoiLCJpc3N1ZWQiOiIyMDIzLTAyLTIwVDA3OjA3OjE1WiIsInZhbGlkRnJvbSI6IjIwMjMtMDItMjBUMDc6MDc6MTVaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTA4LTIxVDA3OjA3OjE1WiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmVic2k6endra3hNZW1ZY2o5bnExWHNxVDZTVkcifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YyL3NjaGVtYXMvejNNZ1VGVWtiNzIydXE0eDNkdjV5QUptbk5tekRGZUs1VUM4eDgzUW9lTEpNIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9fX0.iHxamFYW8uQTzdgY5pTQkSfQYkMZmexVG9keUMPgo4FntobCOG4aoZ2inn73ZK349xHn6MQ0oeRHU4zdmqVqCA"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	ebsiTrustList := ebsi.NewEBSITrustList(
		ebsi.WithBaseUrl(ts.URL),
		ebsi.WithAuthToken("eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJvbmJvYXJkaW5nIjoicmVjYXB0Y2hhIiwidmFsaWRhdGVkSW5mbyI6eyJzdWNjZXNzIjp0cnVlLCJjaGFsbGVuZ2VfdHMiOiIyMDIzLTAyLTIwVDA3OjA3OjA4WiIsImhvc3RuYW1lIjoiYXBwLXBpbG90LmVic2kuZXUiLCJzY29yZSI6MC45LCJhY3Rpb24iOiJsb2dpbiJ9LCJpc3MiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSIsImlhdCI6MTY3Njg3NjgyOSwiZXhwIjoxNjc2ODc3NzI5fQ.GBcksNkxb4FGSP_43mDO_XuQXs0lnPERZ6Q45rjAc-OdDhM0BgBYCIzBYSP3G1JKfAv6ObtaztypG4PvZZyoeQ"),
		ebsi.WithHttpClient(ts.Client()),
	)
	jwkKey, _ := jwk.ParseKey([]byte(jwkKeyString))
	_, err := ebsiTrustList.Onboard("did:ebsi:123", jwkKey)

	require.NoError(t, err)
}

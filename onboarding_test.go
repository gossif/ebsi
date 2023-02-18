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
	var jwkKeyString string = `{"crv":"secp256k1","d":"795zTlL1wugU-REjsn0jzUSZKkgx4v5MED4az_8Vld4","kid":"did:ebsi:123#5e03672cf37c48a285bb477fc2e4245a","kty":"EC","x":"_4yJo7b0vLgY6TalpURqLR4hEUTwhNzGmEfGVVugXIU","y":"27xpTouz2D_X4cxzydSR9M7HMQJg992GjJINvVyydhc"}`

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users-onboarding/v1/authentication-requests":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"session_token": "openid://?response_type=id_token&client_id=https%3A%2F%2Fapi.preprod.ebsi.eu%2Fusers-onboarding%2Fv2%2Fauthentication-responses&scope=openid+did_authn&nonce=03ac5101-0e76-4169-acfb-c4956938a69e&request=eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJodHRwczovL2FwaS5wcmVwcm9kLmVic2kuZXUvdHJ1c3RlZC1hcHBzLXJlZ2lzdHJ5L3YzL2FwcHMvdXNlcnMtb25ib2FyZGluZy1hcGlfcGlsb3QtdGVtcC0wMSJ9.eyJzY29wZSI6Im9wZW5pZCBkaWRfYXV0aG4iLCJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoicG9zdCIsImNsaWVudF9pZCI6Imh0dHBzOi8vYXBpLnByZXByb2QuZWJzaS5ldS91c2Vycy1vbmJvYXJkaW5nL3YyL2F1dGhlbnRpY2F0aW9uLXJlc3BvbnNlcyIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vYXBpLnByZXByb2QuZWJzaS5ldS91c2Vycy1vbmJvYXJkaW5nL3YyL2F1dGhlbnRpY2F0aW9uLXJlc3BvbnNlcyIsIm5vbmNlIjoiMDNhYzUxMDEtMGU3Ni00MTY5LWFjZmItYzQ5NTY5MzhhNjllIiwiaWF0IjoxNjYwODUwNzQ5LCJpc3MiOiJ1c2Vycy1vbmJvYXJkaW5nLWFwaV9waWxvdC10ZW1wLTAxIiwiZXhwIjoxNjYwODUxMDQ5fQ.nExUW_MZJeyMtJlZEO-ZFIlHay56u5z1KWkKPWViccav04UWhqn9HFH8oQa86miIW10SBXcCoq9bT1aQCSFnZA"}`))

		case "/users-onboarding/v1/authentication-responses":
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
			assert.EqualValues(t, "03ac5101-0e76-4169-acfb-c4956938a69e", nonce)

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"verifiableCredential":"eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJqdGkiOiJ2YzplYnNpOmF1dGhlbnRpY2F0aW9uIzNmZjJlY2QzLWEwMWMtNDgwOC1iMDY5LTU2NjY5MDI2NjdmNCIsInN1YiI6ImRpZDplYnNpOnpiTThjQ3VvQk1GTkxlUXlMaVZGeXh3IiwiaXNzIjoiZGlkOmVic2k6enIycldESEhyVUNkWkFXN3dzU2I1blEiLCJuYmYiOjE2NzI5MDkyNjMsImV4cCI6MTY4ODYzNDA2MywiaWF0IjoxNjcyOTA5MjYzLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6InZjOmVic2k6YXV0aGVudGljYXRpb24jM2ZmMmVjZDMtYTAxYy00ODA4LWIwNjktNTY2NjkwMjY2N2Y0IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdXRob3Jpc2F0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnpyMnJXREhIclVDZFpBVzd3c1NiNW5RIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0wNVQwOTowMTowM1oiLCJpc3N1ZWQiOiIyMDIzLTAxLTA1VDA5OjAxOjAzWiIsInZhbGlkRnJvbSI6IjIwMjMtMDEtMDVUMDk6MDE6MDNaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTA3LTA2VDA5OjAxOjAzWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmVic2k6emJNOGNDdW9CTUZOTGVReUxpVkZ5eHcifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YyL3NjaGVtYXMvekhNcDUyTHFKV29jbWhBOVJrem5UV3VFZWNKWG9QREt3M2tXUXA4MVlZOXBDIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9fX0.1jngGGWZF9W8AJXrzJkiscqI9BSsrJIejwsWnyhztAtiG7Ym5ZT9NlHNnSCV9zDrWDOO5idLUuaW5T0gZyYBXw"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	ebsiTrustList := ebsi.NewEBSITrustList(
		ebsi.WithBaseUrl(ts.URL),
		ebsi.WithAuthToken("undefined"),
		ebsi.WithHttpClient(ts.Client()),
	)
	jwkKey, _ := jwk.ParseKey([]byte(jwkKeyString))
	_, err := ebsiTrustList.Onboard(jwkKey)

	require.NoError(t, err)
}

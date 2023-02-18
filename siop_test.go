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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAccessCode(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"succesful": testAuthorizationRequestSucceeded,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testAuthorizationRequestSucceeded(t *testing.T) {
	var (
		jsonSigningKey      string = `{"crv": "secp256k1","d":"795zTlL1wugU-REjsn0jzUSZKkgx4v5MED4az_8Vld4","kid":"did:ebsi:123#5e03672cf37c48a285bb477fc2e4245a","kty":"EC","x":"_4yJo7b0vLgY6TalpURqLR4hEUTwhNzGmEfGVVugXIU","y":"27xpTouz2D_X4cxzydSR9M7HMQJg992GjJINvVyydhc"}`
		jsonEncryptionKey   string = `{"crv": "secp256k1","d":"2eSY9AeVE_r_9LIULFZ-trEZE8KFW7VbobTCm3BvaS0","kid":"did:ebsi:123#d39bb517b9fb4a49aae6bb5ff033717a","kty":"EC","x":"wpO8Q_KOaCEAh-lP8JrIQcnY-acy50gyOKUzGHp_mvU","y":"piBIQXT5ydXePsYD21D_hgbWJJuorirM-GoLNs3_I90"}`
		expectedAke1Payload        = map[string]interface{}{
			"ake1_enc_payload": "49e6dfa1ecac5b6310d82ed10122ca86036fa0f5ea7c4ca6fa963980cdac2327e6e576c9d7858db0264fe75705e482753c12960cff53f27622dc54eb5447f3bec45e432e500fba54c3c823e451d56e5e695316cc36e4a57e3fad669f9c5fe80908a4a8cb092cea93f61b05605c163ed8e87ee7f47979ef047bdcf7dbd89dd5fdc0365d3045be1a2c2056875cd745cdbf678cca170b55606620152d87519137aa3d2c681a353c8e8a89baca72fa9d4679ea34d5c8958d9a00b93bbb683c98d54869719ce843e314eda690a72c196bd573be4e438bd125bde5623e146be0bc1b01a147c98723b22f0e681243bc84ca0c155ff85650f51bf153f3244a408f45ef3fc6ae311eca98597befebd5ea8c22bc3fccae8e4b810aebceca68dac9ee01108497615c07080c69cc7b3ccaea898cd1ae6d39bff622b9be5725764909de818232c8341038d6ea42da56b8d0939e9420ff34896a3306ce6595388d3adf66872b7f9730cf565cb4de09a58cd09a52a92680cbaa130a4f04abed498de4cc3f6078a1075c817d17a99de63a7ec219814d388de54b7a8f06aadded4fa80d8016d152107c8637bca58c49446b8c2a21a4ff5eaaaccf45d642b2995417ea206537533eac60e85f62e0c681ff6893e29b4c90268cf898f09944e257922ba33d467b92ad49b0fadfe9de41f74e24c3f549dfd356f2e9268ac6a379196d29a4932024f7f052d80e32b33892e1119bc0933e0b8aefbb6fc9c2cf93a24d0bbafe9836652dda69f87adc1c2695a70a35fd38cf4f605a031152610e30b7c9807b4219fc5b15f3354a15e9ef60c16c79b6b327104103e831e048af3b51523f7f8beed452c0694974ceafdbdc824e50e9fafd87d35a2813a922ac790f59341e8378b57bfddd102630486174e69a7e71c12898addf4fe7d973a51bafcb6c0f5325e77269802c314dd667f646696b19e84d98cd69b01cc0ab1b0448608956d9fafa98cc94aadb7c148d2ac57eff3a3d23749591921ee3717120b823dec14b0655bad710e97d95dcce5ab3e6f168d5efe5268e3d713aa0602ee08d89341684dd8dbab2dd60212729dccf4fe08a0e55166c6de004143dc2a8790319f4230d448b1508e45eb27925886ed2c3",
			"ake1_sig_payload": map[string]interface{}{
				"iat":              1662069647,
				"exp":              1662070547,
				"ake1_nonce":       "udcCW61Goa46ikws9k3y-T6o4b9Cl6Ng81V5HXwmjEI=",
				"ake1_enc_payload": "49e6dfa1ecac5b6310d82ed10122ca86036fa0f5ea7c4ca6fa963980cdac2327e6e576c9d7858db0264fe75705e482753c12960cff53f27622dc54eb5447f3bec45e432e500fba54c3c823e451d56e5e695316cc36e4a57e3fad669f9c5fe80908a4a8cb092cea93f61b05605c163ed8e87ee7f47979ef047bdcf7dbd89dd5fdc0365d3045be1a2c2056875cd745cdbf678cca170b55606620152d87519137aa3d2c681a353c8e8a89baca72fa9d4679ea34d5c8958d9a00b93bbb683c98d54869719ce843e314eda690a72c196bd573be4e438bd125bde5623e146be0bc1b01a147c98723b22f0e681243bc84ca0c155ff85650f51bf153f3244a408f45ef3fc6ae311eca98597befebd5ea8c22bc3fccae8e4b810aebceca68dac9ee01108497615c07080c69cc7b3ccaea898cd1ae6d39bff622b9be5725764909de818232c8341038d6ea42da56b8d0939e9420ff34896a3306ce6595388d3adf66872b7f9730cf565cb4de09a58cd09a52a92680cbaa130a4f04abed498de4cc3f6078a1075c817d17a99de63a7ec219814d388de54b7a8f06aadded4fa80d8016d152107c8637bca58c49446b8c2a21a4ff5eaaaccf45d642b2995417ea206537533eac60e85f62e0c681ff6893e29b4c90268cf898f09944e257922ba33d467b92ad49b0fadfe9de41f74e24c3f549dfd356f2e9268ac6a379196d29a4932024f7f052d80e32b33892e1119bc0933e0b8aefbb6fc9c2cf93a24d0bbafe9836652dda69f87adc1c2695a70a35fd38cf4f605a031152610e30b7c9807b4219fc5b15f3354a15e9ef60c16c79b6b327104103e831e048af3b51523f7f8beed452c0694974ceafdbdc824e50e9fafd87d35a2813a922ac790f59341e8378b57bfddd102630486174e69a7e71c12898addf4fe7d973a51bafcb6c0f5325e77269802c314dd667f646696b19e84d98cd69b01cc0ab1b0448608956d9fafa98cc94aadb7c148d2ac57eff3a3d23749591921ee3717120b823dec14b0655bad710e97d95dcce5ab3e6f168d5efe5268e3d713aa0602ee08d89341684dd8dbab2dd60212729dccf4fe08a0e55166c6de004143dc2a8790319f4230d448b1508e45eb27925886ed2c3",
				"did":              "did:ebsi:ztXSxNw2AJPw1CyLjjCgcSK",
				"iss":              "did:ebsi:znHeZWvhAK2FK2Dk1jXNe7m",
			},
			"ake1_jws_detached": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJodHRwczovL2FwaS5wcmVwcm9kLmVic2kuZXUvdHJ1c3RlZC1hcHBzLXJlZ2lzdHJ5L3YyL2FwcHMvMHg1NTljNGYzMmRjMzU1NjZlNGI5MmI2OTc0OTljMzhmMzg0N2E2YzUzZjgzNDQ4MjFjMjQzNTRlYWQxZjJhYjFlIn0..kv_F9pQN3gERG5usVudN9mm4aZ-yZ53KGvczJ7fdY1F-PhK2ogss5gx7qre_1E0RUtgBAsaR32lrCKHlHbthAg",
			"did":               "did:ebsi:znHeZWvhAK2FK2Dk1jXNe7m",
		}
	)
	expectedPath := "/authorisation/v1/siop-sessions"

	expectedAke1PayloadBytes, err := json.Marshal(expectedAke1Payload)
	require.Nil(t, err)

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorisation/v1/siop-sessions":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(expectedAke1PayloadBytes))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != expectedPath {
			w.WriteHeader(http.StatusMethodNotAllowed)
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
	did := "did:ebsi:123"
	verifiableCredential := "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QiLCJraWQiOiJkaWQ6ZWJzaTp6cjJyV0RISHJVQ2RaQVc3d3NTYjVuUSNrZXlzLTEifQ.eyJqdGkiOiJ2YzplYnNpOmF1dGhlbnRpY2F0aW9uIzNmZjJlY2QzLWEwMWMtNDgwOC1iMDY5LTU2NjY5MDI2NjdmNCIsInN1YiI6ImRpZDplYnNpOnpiTThjQ3VvQk1GTkxlUXlMaVZGeXh3IiwiaXNzIjoiZGlkOmVic2k6enIycldESEhyVUNkWkFXN3dzU2I1blEiLCJuYmYiOjE2NzI5MDkyNjMsImV4cCI6MTY4ODYzNDA2MywiaWF0IjoxNjcyOTA5MjYzLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJpZCI6InZjOmVic2k6YXV0aGVudGljYXRpb24jM2ZmMmVjZDMtYTAxYy00ODA4LWIwNjktNTY2NjkwMjY2N2Y0IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdXRob3Jpc2F0aW9uIl0sImlzc3VlciI6ImRpZDplYnNpOnpyMnJXREhIclVDZFpBVzd3c1NiNW5RIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMS0wNVQwOTowMTowM1oiLCJpc3N1ZWQiOiIyMDIzLTAxLTA1VDA5OjAxOjAzWiIsInZhbGlkRnJvbSI6IjIwMjMtMDEtMDVUMDk6MDE6MDNaIiwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTA3LTA2VDA5OjAxOjAzWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmVic2k6emJNOGNDdW9CTUZOTGVReUxpVkZ5eHcifSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6Imh0dHBzOi8vYXBpLXBpbG90LmVic2kuZXUvdHJ1c3RlZC1zY2hlbWFzLXJlZ2lzdHJ5L3YyL3NjaGVtYXMvekhNcDUyTHFKV29jbWhBOVJrem5UV3VFZWNKWG9QREt3M2tXUXA4MVlZOXBDIiwidHlwZSI6IkZ1bGxKc29uU2NoZW1hVmFsaWRhdG9yMjAyMSJ9fX0.1jngGGWZF9W8AJXrzJkiscqI9BSsrJIejwsWnyhztAtiG7Ym5ZT9NlHNnSCV9zDrWDOO5idLUuaW5T0gZyYBXw"
	jwkSigningKey, err := jwk.ParseKey([]byte(jsonSigningKey))
	require.NoError(t, err)
	jwkEncryptionKey, err := jwk.ParseKey([]byte(jsonEncryptionKey))
	require.NoError(t, err)
	ak1Decrypted, err := ebsiTrustList.GetAccessToken(did, verifiableCredential, jwkSigningKey, jwkEncryptionKey)

	assert.NoError(t, err)
	assert.NotEmpty(t, ak1Decrypted)
}

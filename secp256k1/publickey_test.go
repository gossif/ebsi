// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package secp256k1_test

import (
	"encoding/json"
	"testing"

	"github.com/gossif/ebsi/secp256k1"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testingReceiverPubkeyHex = "03879f05a964ea522a2bcbcf3d78ad7ac0413edb9ceaed14057510d2c6174b8e42"

const signatureSecp256k1PublicKeyRaw = `{
	"crv": "secp256k1",
	"kid": "did:ebsi:zfAgpuXjMpXj1PpTjL8ggxc#165892779e384e3fa24c541e66b6fd68",
	"kty": "EC",
	"x":   "CIfoy0YIGuX9hcSzoKVOlpEXgvMiKpoSTBaXleMhKLQ",
	"y":   "ZEnJN1avCJBdZxWmONaWIVI1MQRZrcmcvq9nTiWcU30"
}`

const signedToken string = "eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidXNlcnMiXSwiY2xhaW0xIjoidmFsdWUxIiwiY2xhaW0yIjoidmFsdWUyIiwiaXNzIjoiZ2l0aHViLmNvbS9sZXN0cnJhdC1nby9qd3gifQ.ak2Kw0UT6Po_lZmkeZwxY5GgxUaX1T6EQweQGA61WmSmOj8ltVyQ81f9H_4TE6eXtB3-AKGH_6AqqbFBD6zbKw"

func TestNewPublicKeyFromHex(t *testing.T) {
	_, err := secp256k1.NewPublicKeyFromHex(testingReceiverPubkeyHex)
	assert.NoError(t, err)
}

func TestPublicKey_Equals(t *testing.T) {
	privkey, err := secp256k1.GeneratePrivateKey()
	if !assert.NoError(t, err) {
		return
	}
	publicKey := privkey.PublicKey
	p := secp256k1.PublicKey{PublicKey: &publicKey}
	assert.True(t, p.Equals(&publicKey))
}

func TestGetAdress(t *testing.T) {
	testdata := `{"crv":"secp256k1","kid":"did:ebsi:123#5e03672cf37c48a285bb477fc2e4245a","kty":"EC","x":"_4yJo7b0vLgY6TalpURqLR4hEUTwhNzGmEfGVVugXIU","y":"27xpTouz2D_X4cxzydSR9M7HMQJg992GjJINvVyydhc"}`
	jwkKey, err := jwk.ParseKey([]byte(testdata))
	require.Nil(t, err)
	expectedAddress := "0x33366e0869cAc6E7fea527B4b02f4e20F3239528"

	pubKey, err := secp256k1.NewPublicKeyFromJwk(jwkKey)
	require.Nil(t, err)

	actualAddress, err := pubKey.GetAdress()
	assert.NoError(t, err)
	assert.EqualValues(t, expectedAddress, actualAddress)
}

func TestVerifySignature(t *testing.T) {
	pubKey := secp256k1.PublicKey{}
	err := json.Unmarshal([]byte(signatureSecp256k1PublicKeyRaw), &pubKey)
	require.NoError(t, err)
	// signed and return a jwt
	err = pubKey.Verify([]byte(signedToken))
	require.NoError(t, err)
}

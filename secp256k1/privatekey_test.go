// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package secp256k1_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gossif/ebsi/secp256k1"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var signatureSecp256k1KeyRaw = `{
	"crv": "secp256k1",
	"d":   "gxRGE34iWo4xRnq0aS2gTA5qeheqcGaf0itymDS6-x4",
	"kid": "did:ebsi:zfAgpuXjMpXj1PpTjL8ggxc#165892779e384e3fa24c541e66b6fd68",
	"kty": "EC",
	"x":   "CIfoy0YIGuX9hcSzoKVOlpEXgvMiKpoSTBaXleMhKLQ",
	"y":   "ZEnJN1avCJBdZxWmONaWIVI1MQRZrcmcvq9nTiWcU30"
}`

var testingReceiverPrivkeyMap = map[string]interface{}{
	"crv": "secp256k1",
	"d":   "gxRGE34iWo4xRnq0aS2gTA5qeheqcGaf0itymDS6-x4",
	"kid": "did:ebsi:zfAgpuXjMpXj1PpTjL8ggxc#165892779e384e3fa24c541e66b6fd68",
	"kty": "EC",
	"x":   "CIfoy0YIGuX9hcSzoKVOlpEXgvMiKpoSTBaXleMhKLQ",
	"y":   "ZEnJN1avCJBdZxWmONaWIVI1MQRZrcmcvq9nTiWcU30",
}

const testingReceiverPrivkeyHex = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d"

func TestGenerateJWK(t *testing.T) {
	var (
		expectedDidController string = "did:ebsi:123"
	)
	privKey, err := secp256k1.GeneratePrivateKey()
	require.Nil(t, err)

	jwkKey, err := privKey.Jwk(expectedDidController)
	require.Nil(t, err)
	require.NotNil(t, jwkKey)

	// test that the first part of the kid equals the did
	actualValue := strings.Split(jwkKey.KeyID(), "#")
	assert.EqualValues(t, expectedDidController, actualValue[0])

}

func TestFromHexToJwk(t *testing.T) {
	var (
		expectedDidController string = "did:ebsi:123"
		privateKeyHex         string = "76d52f0bdc165d346b8320b31e2d1d84149e513374d191f9624024ddbddec45c"
	)
	privKey, err := secp256k1.NewPrivateKeyFromHex(privateKeyHex)
	require.NoError(t, err)
	_, err = privKey.Jwk(expectedDidController)
	require.Nil(t, err)
}

func TestNewPrivateKeyFromHex(t *testing.T) {
	_, err := secp256k1.NewPrivateKeyFromHex(testingReceiverPrivkeyHex)
	assert.NoError(t, err)
}

func TestNewPrivateKeyFromMap(t *testing.T) {
	_, err := secp256k1.NewPrivateKeyFromMap(testingReceiverPrivkeyMap)
	assert.NoError(t, err)
}

func TestPrivateKeyHex(t *testing.T) {
	privkey, err := secp256k1.GeneratePrivateKey()
	if !assert.NoError(t, err) {
		return
	}
	p := secp256k1.PrivateKey{PrivateKey: privkey.PrivateKey}
	hexKey := p.Hex()
	assert.NotEmpty(t, hexKey)
}

func TestPrivateKeyEquals(t *testing.T) {
	privkey, err := secp256k1.GeneratePrivateKey()
	if !assert.NoError(t, err) {
		return
	}
	p := secp256k1.PrivateKey{PrivateKey: privkey.PrivateKey}
	assert.True(t, p.Equals(privkey.PrivateKey))
}

func TestSigning(t *testing.T) {
	// create a new jwt
	token, err := jwt.NewBuilder().
		Claim("nonce", "mygeneratednonce").
		Issuer("example.com").
		Audience([]string{"users"}).
		Build()

	require.NoError(t, err)

	privKey := secp256k1.PrivateKey{}
	err = json.Unmarshal([]byte(signatureSecp256k1KeyRaw), &privKey)
	require.NoError(t, err)
	// signed and return a jwt
	actualSignedSecp256k1, err := privKey.Sign(token)
	require.NoError(t, err)
	assert.NotEmpty(t, actualSignedSecp256k1)
	t.Log(string(actualSignedSecp256k1.([]byte)))
}

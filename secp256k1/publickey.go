// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package secp256k1

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// PublicKey instance with nested elliptic.Curve interface (secp256k1 instance in our case)
type PublicKey struct {
	*ecdsa.PublicKey
	// Needed to include because information is lost when transforming between jwk and ecdsa
	JwkKey jwk.Key
}

func SetPublicKey(pub *ecdsa.PublicKey) *PublicKey {
	return &PublicKey{PublicKey:pub}
}

// NewPublicKeyFromHex decodes hex form of public key raw bytes and returns PublicKey instance
func NewPublicKeyFromHex(pubHex string) (*PublicKey, error) {
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}
	pubKey, err := NewPublicKeyFromBytes(pubBytes)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// NewPublicKeyFromBytes decodes public key raw bytes and returns PublicKey instance;
// Supports both compressed and uncompressed public keys
func NewPublicKeyFromBytes(pubBytes []byte) (*PublicKey, error) {
	pubECDSA, err := ethcrypto.DecompressPubkey(pubBytes)
	if err != nil {
		return nil, err
	}
	pubKey := SetPublicKey(pubECDSA)
	return pubKey, nil
}

func NewPublicKeyFromJwk(pubJwk jwk.Key) (*PublicKey, error) {
	var (
		keyECDSA ecdsa.PublicKey
	)
	err := pubJwk.Raw(&keyECDSA)
	if err != nil {
		return nil, err
	}
	jwkKeyMap, _ := pubJwk.AsMap(context.TODO())
	if curve, exists := jwkKeyMap["crv"]; exists {
		switch curve.(jwa.EllipticCurveAlgorithm) {
		case Secp256k1:
			// set the signature algorithm,
			// set the signature algorithm,
			pubJwk.Set("alg", jwa.ES256K)
			pubKey := SetPublicKey(&keyECDSA)
			pubKey.JwkKey = pubJwk
			return pubKey, nil
		default:
			return nil, errors.New("curve must be Secp256k1")
		}
	}
	return nil, errors.New("curve not found in jwk key")
}

// NewPublicKeyFromMap decodes public key from a map, map must be a valid json web key
func NewPublicKeyFromMap(pubMap map[string]interface{}) (*PublicKey, error) {
	var (
		pubKey PublicKey
	)
	bytes, err := json.Marshal(pubMap)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &pubKey)
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}

// Bytes returns public key raw bytes;
// Could be optionally compressed by dropping Y part
func (k *PublicKey) Bytes(compressed bool) []byte {
	if compressed {
		return ethcrypto.CompressPubkey(k.PublicKey)
	} else {
		return ethcrypto.FromECDSAPub(k.PublicKey)
	}
}

// Jwk returns public key as json web key
func (k *PublicKey) Jwk() (jwk.Key, error) {
	if k.JwkKey != nil {
		return k.JwkKey, nil
	}
	jwkKey, err := jwk.FromRaw(k.PublicKey)
	if err != nil {
		return nil, err
	}
	return jwkKey, err
}

func (k *PublicKey) UnmarshalJSON(data []byte) error {
	jwkKey, err := jwk.ParseKey(data)
	if err != nil {
		return err
	}
	pubKey, err := NewPublicKeyFromJwk(jwkKey)
	if err != nil {
		return err
	}
	k.PublicKey = pubKey.PublicKey
	k.JwkKey = pubKey.JwkKey
	return nil
}

func (k *PublicKey) MarshalJSON() ([]byte, error) {
	var (
		jwkKey jwk.Key
	)
	if k.JwkKey != nil {
		return json.Marshal(k.JwkKey)
	}
	jwkKey, err := jwk.FromRaw(k.PublicKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(jwkKey)
}

// Hex returns public key bytes in hex form
func (k *PublicKey) Hex(compressed bool) string {
	return hex.EncodeToString(k.Bytes(compressed))
}

// Decapsulate decapsulates key by using Key Encapsulation Mechanism and returns symmetric key;
// can be safely used as encryption key
func (k *PublicKey) ECDH(priv *ecdsa.PrivateKey) ([]byte, error) {
	return SetPrivateKey(priv).ECDH(k.PublicKey)
}

// GetAdress gets the ethereum address of the public key
func (k *PublicKey) GetAdress() (string, error) {
	address := ethcrypto.PubkeyToAddress(*k.PublicKey).Hex()
	return address, nil
}

// Equals compares two public keys with constant time (to resist timing attacks)
func (k *PublicKey) Equals(pub *ecdsa.PublicKey) bool {
	eqX := subtle.ConstantTimeCompare(k.X.Bytes(), pub.X.Bytes()) == 1
	eqY := subtle.ConstantTimeCompare(k.Y.Bytes(), pub.Y.Bytes()) == 1
	return eqX && eqY
}

// Verify will verify a signed token with the public key.
func (k *PublicKey) Verify(signed interface{}, options ...jwt.ParseOption) error {
	publicKey, err := k.Jwk()
	if err != nil {
		return err
	}
	options = append(options, jwt.WithKey(jwa.ES256K, publicKey))
	switch signed := signed.(type) {
	case string:
		_, err := jwt.Parse([]byte(signed), options...)

		if err != nil {
			return err
		}
		return nil
	case []byte:
		_, err := jwt.Parse(signed, options...)

		if err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("signed token has not a supported type (%T)", signed)
}

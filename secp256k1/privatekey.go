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
	"strings"

	secp256k1v4 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const Secp256k1 jwa.EllipticCurveAlgorithm = "secp256k1"

// PrivateKey is an instance of secp256k1 private key with nested public key
type PrivateKey struct {
	*ecdsa.PrivateKey
	// Needed to include because information is lost when transforming between jwk and ecdsa
	JwkKey jwk.Key
}

func SetPrivateKey(priv *ecdsa.PrivateKey) *PrivateKey {
	return &PrivateKey{PrivateKey: priv}
}

// GenerateKey generates secp256k1 key pair
func GeneratePrivateKey() (*PrivateKey, error) {
	// neeed to use the key generation from github.com/decred/dcrd/dcrec/secp256k1/v4. Otherwise error on checking curve
	// the lesstrat/jwx library uses this crypto to check the elliptic curve
	// decred uses koblitz curve as type, go-ethereum bitcurve
	rawKey, err := secp256k1v4.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	privKey := SetPrivateKey(rawKey.ToECDSA())
	return privKey, nil
}

// GeneratePrivateKeyAsJwk generates secp256k1 key pair and returns private key as json web key
func GeneratePrivateKeyAsJwk(didController string) (jwk.Key, error) {
	key, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return key.Jwk(didController)
}

func NewPrivateKeyFromJwk(privJwk jwk.Key) (*PrivateKey, error) {
	var (
		keyECDSA ecdsa.PrivateKey
	)
	err := privJwk.Raw(&keyECDSA)
	if err != nil {
		return nil, err
	}
	jwkKeyMap, _ := privJwk.AsMap(context.TODO())
	if curve, exists := jwkKeyMap["crv"]; exists {
		switch curve.(jwa.EllipticCurveAlgorithm) {
		case Secp256k1:
			// set the signature algorithm,
			privJwk.Set("alg", jwa.ES256K)
			privKey := SetPrivateKey(&keyECDSA)
			privKey.JwkKey = privJwk
			return privKey, nil
		default:
			return nil, errors.New("curve must be Secp256k1")
		}
	}
	return nil, errors.New("curve not found in jwk key")
}

// NewPrivateKeyFromHex decodes hex form of private key raw bytes, computes public key and returns PrivateKey instance
func NewPrivateKeyFromHex(privHex string) (*PrivateKey, error) {
	bytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, err
	}
	privKey, _ := NewPrivateKeyFromBytes(bytes)
	return privKey, nil
}

// NewPrivateKeyFromBytes decodes private key raw bytes, computes public key and returns PrivateKey instance
func NewPrivateKeyFromBytes(privBytes []byte) (*PrivateKey, error) {
	rawKey := secp256k1v4.PrivKeyFromBytes(privBytes)
	privKey := SetPrivateKey(rawKey.ToECDSA())
	return privKey, nil
}

// NewPrivateKeyFromMap decodes private key from a map, map must be a valid json web key
func NewPrivateKeyFromMap(privMap map[string]interface{}) (*PrivateKey, error) {
	var (
		privKey PrivateKey
	)
	bytes, err := json.Marshal(privMap)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &privKey)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func (k *PrivateKey) UnmarshalJSON(data []byte) error {
	jwkKey, err := jwk.ParseKey(data)
	if err != nil {
		return err
	}
	privKey, err := NewPrivateKeyFromJwk(jwkKey)
	if err != nil {
		return err
	}
	k.PrivateKey = privKey.PrivateKey
	k.JwkKey = privKey.JwkKey
	return nil
}

func (k *PrivateKey) MarshalJSON() ([]byte, error) {
	var (
		jwkKey jwk.Key
	)
	if k.JwkKey != nil {
		return json.Marshal(k.JwkKey)
	}
	jwkKey, err := jwk.FromRaw(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(jwkKey)
}

// Jwk returns private key as json web key
func (k *PrivateKey) Jwk(didController string) (jwk.Key, error) {
	kid := didController + "#" + strings.Replace(uuid.NewString(), "-", "", -1)
	jwkKey, err := jwk.FromRaw(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.KeyIDKey, kid)
	k.JwkKey = jwkKey
	return jwkKey, err
}

// Bytes returns private key raw bytes
func (k *PrivateKey) Bytes() []byte {
	return ethcrypto.FromECDSA(k.PrivateKey)
}

// Hex returns private key bytes in hex form
func (k *PrivateKey) Hex() string {
	return hex.EncodeToString(k.Bytes())
}

// ECDH encapsulates key by using Key Encapsulation Mechanism and returns symmetric key;
// can be safely used as encryption key
func (k *PrivateKey) ECDH(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is empty")
	}
	// Shared secret generation
	sx, sy := pub.Curve.ScalarMult(pub.X, pub.Y, k.D.Bytes())

	var ss []byte
	if sy.Bit(0) != 0 { // If odd
		ss = append(ss, 0x03)
	} else { // If even
		ss = append(ss, 0x02)
	}

	// Sometimes shared secret is less than 32 bytes; Big Endian
	l := len(pub.Curve.Params().P.Bytes())
	for i := 0; i < l-len(sx.Bytes()); i++ {
		ss = append(ss, 0x00)
	}

	return append(ss, sx.Bytes()...), nil
}

// Equals compares two private keys with constant time (to resist timing attacks)
func (k *PrivateKey) Equals(priv *ecdsa.PrivateKey) bool {
	return subtle.ConstantTimeCompare(k.D.Bytes(), priv.D.Bytes()) == 1
}

// Sign signs the payload, jwt (payload is jwt.Token) and linked data proof are supported (payload is map[string]interface)
func (k *PrivateKey) Sign(payload interface{}) (interface{}, error) {
	if k.JwkKey == nil {
		return nil, errors.New("private key must have a json web key with a key id")
	}
	switch payload := payload.(type) {
	case jwt.Token:
		serialized, err := jwt.Sign(payload, jwt.WithKey(jwa.ES256K, k.JwkKey))
		if err != nil {
			return nil, err
		}
		return serialized, nil
	}
	return nil, fmt.Errorf("payload has not a supported type (%T)", payload)
}

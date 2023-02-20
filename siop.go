// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gossif/ebsi/secp256k1"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type ake1SigPayload struct {
	IssuedAt         int64  `json:"iat"`
	ExpirationTime   int64  `json:"exp"`
	Nonce            string `json:"ake1_nonce"`
	EncryptedPayload string `json:"ake1_enc_payload"`
	Did              string `json:"did"`
	Issuer           string `json:"iss"`
}

type ake1Payload struct {
	EncryptedPayload string         `json:"ake1_enc_payload"`
	Signature        ake1SigPayload `json:"ake1_sig_payload"`
	JwsDetached      string         `json:"ake1_jws_detached"`
	Did              string         `json:"did"`
}

type ake1Decrypted struct {
	AccessToken string `json:"access_token"`
	Nonce       string `json:"nonce"`
	Did         string `json:"did"`
}

func (e *ebsiTrustList) getAccessToken(r registration) (*ake1Decrypted, error) {
	var (
		ake1Payload *ake1Payload
	)
	idToken, err := generateIdToken(r.Identifier, r.SigningKey, r.EncryptionKey)
	if err != nil {
		return nil, err
	}
	vpToken, err := generateVpToken(r.Identifier, r.Token, r.SigningKey)
	if err != nil {
		return nil, err
	}
	ake1Payload, err = e.postCreateSiopSession(context.Background(), idToken, vpToken)
	if err != nil {
		return nil, err
	}
	decryptedPayload, err := handleSiopResponse(ake1Payload, r.EncryptionKey)
	if err != nil {
		return nil, err
	}
	return decryptedPayload, nil
}

// postCreateSiopSession starts the authorization request with ebsi to onboard a user
func (e *ebsiTrustList) postCreateSiopSession(ctx context.Context, idToken, vpToken []byte) (*ake1Payload, error) {
	var (
		ake1Payload ake1Payload
	)
	if err := e.httpPost("/authorisation/v2/siop-sessions", fmt.Sprintf(`{"id_token":"%s","vp_token":"%s"}`, string(idToken), string(vpToken)), &ake1Payload); err != nil {
		return nil, err
	}
	return &ake1Payload, nil
}

func generateIdToken(did string, signingKey, encryptionKey jwk.Key) ([]byte, error) {
	publicEncKey, _ := encryptionKey.PublicKey()
	claims := map[string]interface{}{
		"encryption_key": publicEncKey,
	}
	publicSigKey, _ := signingKey.PublicKey()
	thumbprint, _ := signingKey.Thumbprint(crypto.SHA256)
	nonce, _ := generateNonce()
	idToken, err := jwt.NewBuilder().
		Issuer("https://self-issued.me/v2").
		Audience([]string{"/siop-sessions"}).
		Subject(base64.URLEncoding.EncodeToString(thumbprint)).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute*5)).
		Claim("did", did).
		Claim("nonce", nonce).
		Claim("sub_jwk", publicSigKey).
		Claim("claims", claims).
		Build()
	if err != nil {
		return nil, err
	}
	serialized, err := jwt.Sign(idToken, jwt.WithKey(jwa.ES256K, signingKey))
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func generateVpToken(did string, verifiableCredential string, signingKey jwk.Key) ([]byte, error) {
	presentation := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1"},
		"type":                 []string{"VerifiablePresentation"},
		"holder":               did,
		"verifiableCredential": []string{verifiableCredential},
	}
	vpToken, err := jwt.NewBuilder().
		Issuer(did).
		JwtID(fmt.Sprintf("urn:uuid:%s", uuid.NewString())).
		Audience([]string{"/siop-sessions"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Minute*5)).
		Claim("vp", presentation).
		Build()

	if err != nil {
		return nil, err
	}
	serialized, err := jwt.Sign(vpToken, jwt.WithKey(jwa.ES256K, signingKey))
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func handleSiopResponse(ake1Payload *ake1Payload, encryptionKey jwk.Key) (*ake1Decrypted, error) {
	var (
		decrypted ake1Decrypted
	)
	// decrypt the encrypted siop response
	plainBytes, err := ake1Decrypt(encryptionKey, ake1Payload.EncryptedPayload)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(plainBytes, &decrypted)
	if err != nil {
		return nil, err
	}
	if ake1Payload.Signature.Nonce != decrypted.Nonce {
		return nil, errors.New("nonce encrypted is not equal to nonce send")
	}
	if ake1Payload.Did != decrypted.Did {
		return nil, errors.New("did encrypted is not equal to did received in ake1")
	}
	return &decrypted, nil
}

func ake1Decrypt(encryptionKey jwk.Key, encryptedPayload string) ([]byte, error) {
	var (
		privateKey *secp256k1.PrivateKey
	)
	ciphertext, _ := hex.DecodeString(encryptedPayload)
	privateKey, err := secp256k1.NewPrivateKeyFromJwk(encryptionKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := privateKey.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

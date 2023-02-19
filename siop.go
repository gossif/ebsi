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
	"github.com/gossif/ldproofs"
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

func (e *ebsiTrustList) getAccessToken(did string, verifiableCredential string, signingKey, encryptionKey jwk.Key) (*ake1Decrypted, error) {
	var (
		ake1Payload *ake1Payload
	)
	if signingKey == nil {
		return nil, errors.New("missing_signing_key")
	}
	if encryptionKey == nil {
		return nil, errors.New("missing_encryption_key")
	}
	idToken, err := generateIdToken(did, verifiableCredential, signingKey, encryptionKey)
	if err != nil {
		return nil, err
	}
	ake1Payload, err = e.postCreateSiopSession(context.Background(), idToken)
	if err != nil {
		return nil, err
	}
	decryptedPayload, err := handleSiopResponse(ake1Payload, encryptionKey)
	if err != nil {
		return nil, err
	}
	return decryptedPayload, nil
}

// postCreateSiopSession starts the authorization request with ebsi to onboard a user
func (e *ebsiTrustList) postCreateSiopSession(ctx context.Context, idToken []byte) (*ake1Payload, error) {
	var (
		ake1Payload ake1Payload
	)
	if err := e.httpPost("/authorisation/v1/siop-sessions", fmt.Sprintf(`{"id_token":"%s"}`, string(idToken)), &ake1Payload); err != nil {
		return nil, err
	}
	return &ake1Payload, nil
}

func generateIdToken(did string, verifiableCredential string, signingKey, encryptionKey jwk.Key) ([]byte, error) {
	presentation := map[string]interface{}{
		"@context":             []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":                   fmt.Sprintf("urn:uuid:%s", uuid.NewString()),
		"type":                 []string{"VerifiablePresentation"},
		"holder":               did,
		"verifiableCredential": []string{verifiableCredential},
	}
	jsonPresentation, _ := json.Marshal(presentation)
	doc, err := ldproofs.NewDocument(jsonPresentation)
	if err != nil {
		return nil, err
	}
	jsonKey, _ := json.Marshal(signingKey)
	keyPair := ldproofs.JWKKeyPair{
		Id:         signingKey.KeyID(),
		Type:       signingKey.KeyType().String(),
		Controller: did,
		PrivateKey: jsonKey,
	}
	jsonKeyPair, _ := json.Marshal(keyPair)
	suite := ldproofs.NewJSONWebSignature2020Suite()
	if err := suite.ParseSignatureKey(jsonKeyPair); err != nil {
		return nil, err
	}
	err = doc.AddLinkedDataProof(ldproofs.WithSignatureSuite(suite), ldproofs.WithPurpose(ldproofs.AssertionMethod))
	if err != nil {
		return nil, err
	}
	//jsonSignedPresentation, _ := json.Marshal(doc.GetDocument())

	publicEncKey, _ := encryptionKey.PublicKey()
	claims := map[string]interface{}{
		//"verified_claims": base64.StdEncoding.EncodeToString(jsonSignedPresentation),
		"encryption_key":  publicEncKey,
	}
	publicSigKey, _ := signingKey.PublicKey()
	thumbprint, _ := signingKey.Thumbprint(crypto.SHA256)
	nonce, _ := generateNonce()
	idToken, err := jwt.NewBuilder().
		Issuer("https://self-issued.me/v2").
		Audience([]string{"https://api-pilot.ebsi.eu/authorisation/v2/siop-sessions"}).
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
	fmt.Println(string(plaintext))
	return plaintext, nil
}

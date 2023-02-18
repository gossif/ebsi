// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package secp256k1_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/gossif/ebsi/secp256k1"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testingAke1Payload map[string]interface{} = map[string]interface{}{
	"ake1_enc_payload": "2743b9a7735275294de1e4bfe26f831403865c8bcd4e1c68a766bbde6665bf4a4088e65ef4fe453a513a2cd78d0a8981cd7634655b82cdb0d191adf0d9c715b5353f6db233193682f94000d21d9c3165a91982227b074350c723e8b549aec9e978e99408bf81b785e6c356decae66f310732a19dc412089cc60c580aa3f0cfa3a8caf08e2f31599de5f98921f685330527d70744f9b30d793d37a760daa5a40d6d84989c186d76adb3be898372f4cde98a0a1c8711f98810276a0367261ae8ebb876a80bfb24cbb879b4abd8165854852d4ada9ea79ae58dbba2b50ebc6d9add89a09718e6cdfbac7e64b0aff9ff175c882a12cf9d316775c1fac0d743edf62f1a3b48c82f5178f041eeb072167680b38ca8eb7dc98495152d00a1192bff7362f7e909aea03007d2b1d16f6325b5c061284f7c0306469b63f7c807a38654593c61fbb73a0b54588fb2f91b39d4a35d37041ad156b7257705f430fbf1cdb4c7a3c3b05024cb3e930be2fd683fc83a7923c5d4d1408a547c652b929cc0ff7c68622001b444994f8c49a67855187530f90ae4cba49df35b88f82a96eda051b323f1190c0735ff2cab8d844d73feb35d2fd504543c62e936e033e144f028b54f522c0cd6aa084e0076f2bd33a6baeedccc93c4535ed8e572d1813db87591765d6d9f4a5c924b57b38594b825b54b1ee34bf29c6098747dc444325fab2a7ac965314103680ce808c75c3ab1a8bbb3cd7865f5821bfbafad8a55c150a1e97c4f98968f9dec9289b03cf3a2a76fc567de24a03546287a59955f9375dc2efc681d8a9a59a6a2eb1ed56b30c4bea608a1c4d7a5a2ba32bf3c67dc8ed62da9249c0a71e2f055b0352f571c736bd6bd62337cc4268bea0bf38e765acce9dfaa680a689aae27c0357338286f58ed60c70d62c6e29ea6025e04cc961eece4e8211809632ad89c79353a7f6b94ad088b0a3eb2837b9faeca954f11cb1fcce327d716e1c8a83cf6c91892963e7b03131dbd345075db945af8147ac6be90fcf2cba30c5041cb3e2c2932c116cc26f6ea08521255e2593d8e09036ee46b8c52937017fcb94404fccf64b8fd5dda5d3f8937ba3a05e37753580e8a8fd4d018737463f4b9198eb4b54ace",
	"ake1_sig_payload": map[string]interface{}{
		"iat":              1661867660,
		"exp":              1661868560,
		"ake1_nonce":       "H5l-dlXXWznpXpeCVUuL7ZmuSI29TJDxu0yWoqdU71A=",
		"ake1_enc_payload": "2743b9a7735275294de1e4bfe26f831403865c8bcd4e1c68a766bbde6665bf4a4088e65ef4fe453a513a2cd78d0a8981cd7634655b82cdb0d191adf0d9c715b5353f6db233193682f94000d21d9c3165a91982227b074350c723e8b549aec9e978e99408bf81b785e6c356decae66f310732a19dc412089cc60c580aa3f0cfa3a8caf08e2f31599de5f98921f685330527d70744f9b30d793d37a760daa5a40d6d84989c186d76adb3be898372f4cde98a0a1c8711f98810276a0367261ae8ebb876a80bfb24cbb879b4abd8165854852d4ada9ea79ae58dbba2b50ebc6d9add89a09718e6cdfbac7e64b0aff9ff175c882a12cf9d316775c1fac0d743edf62f1a3b48c82f5178f041eeb072167680b38ca8eb7dc98495152d00a1192bff7362f7e909aea03007d2b1d16f6325b5c061284f7c0306469b63f7c807a38654593c61fbb73a0b54588fb2f91b39d4a35d37041ad156b7257705f430fbf1cdb4c7a3c3b05024cb3e930be2fd683fc83a7923c5d4d1408a547c652b929cc0ff7c68622001b444994f8c49a67855187530f90ae4cba49df35b88f82a96eda051b323f1190c0735ff2cab8d844d73feb35d2fd504543c62e936e033e144f028b54f522c0cd6aa084e0076f2bd33a6baeedccc93c4535ed8e572d1813db87591765d6d9f4a5c924b57b38594b825b54b1ee34bf29c6098747dc444325fab2a7ac965314103680ce808c75c3ab1a8bbb3cd7865f5821bfbafad8a55c150a1e97c4f98968f9dec9289b03cf3a2a76fc567de24a03546287a59955f9375dc2efc681d8a9a59a6a2eb1ed56b30c4bea608a1c4d7a5a2ba32bf3c67dc8ed62da9249c0a71e2f055b0352f571c736bd6bd62337cc4268bea0bf38e765acce9dfaa680a689aae27c0357338286f58ed60c70d62c6e29ea6025e04cc961eece4e8211809632ad89c79353a7f6b94ad088b0a3eb2837b9faeca954f11cb1fcce327d716e1c8a83cf6c91892963e7b03131dbd345075db945af8147ac6be90fcf2cba30c5041cb3e2c2932c116cc26f6ea08521255e2593d8e09036ee46b8c52937017fcb94404fccf64b8fd5dda5d3f8937ba3a05e37753580e8a8fd4d018737463f4b9198eb4b54ace",
		"did":              "did:ebsi:z24dMJ9i1ftxft142R8ARvxj",
		"iss":              "did:ebsi:zcPNLbvojYtj7R3B6pJXaFy",
	},
	"ake1_jws_detached": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksiLCJraWQiOiJodHRwczovL2FwaS50ZXN0LmludGVic2kueHl6L3RydXN0ZWQtYXBwcy1yZWdpc3RyeS92Mi9hcHBzLzB4ZjBjMzRhNzIxZTFiYjc2MDZkZTMzYTZlNDRhYjMwNjk4ZTgwNzZkN2JiNWMwYjExZDEwOGFhNTJhNWRlMDMzNyJ9..GQbDAH6VrRWzYrdko7f1M25NpbmEtAZTZ_Uuex8hCF7wHG5VpjhpvaUkyMIVO9McbOO_9jKDnTWxdyVt-ghdXA",
	"did":               "did:ebsi:zcPNLbvojYtj7R3B6pJXaFy",
}

var testingEncryptionPrivateKey map[string]interface{} = map[string]interface{}{
	"crv": "secp256k1",
	"d":   "Me8CT5KjTXoWYryAGQXrjf2AxU4R_KrAC4M7yQuTUjo",
	"kid": "did:ebsi:z24dMJ9i1ftxft142R8ARvxj#ec2604815ce746f5a429f2ed948f5a7c",
	"kty": "EC",
	"x":   "6cSC4fuQ33YqS-PdUD67wF0CiOp5mnD1GDP_fCSeDNA",
	"y":   "NHhWhLaiFJ0j0n5jpvbGB0fUeaIwjpp9R7kjzcgfpQ4",
}

const testingMessage = "helloworld"
const testingJsonMessage = `{"code":0,"msg":"ok","data":{"pageNumber":1,"pageSize":10,"total":0,"list":[],"realTotal":0}}{"code":0,"msg":"ok","data":{"pageNumber":1,"pageSize":10,"total":0,"list":[],"realTotal":0}}{"code":0,"msg":"ok","data":{"pageNumber":1,"pageSize":10,"total":0,"list":[],"realTotal":0}}`
const expectedDecryptedHex = "7b226163636573735f746f6b656e223a2265794a30655841694f694a4b563151694c434a68624763694f694a46557a49314e6b73694c434a72615751694f694a6f64485277637a6f764c324677615335305a584e304c6d6c756447566963326b7565486c364c33527964584e305a57517459584277637931795a57647063335279655339324d6939686348427a4c7a42345a6a426a4d7a52684e7a49785a544669596a63324d445a6b5a544d7a59545a6c4e445268596a4d774e6a6b345a5467774e7a5a6b4e324a694e574d77596a45785a4445774f4746684e544a684e57526c4d444d7a4e794a392e65794a70595851694f6a45324e6a45344e6a63324e6a4173496d5634634349364d5459324d5467324f4455324d43776963335669496a6f695a476c6b4f6d566963326b36656a49305a45314b4f576b785a6e52345a6e51784e444a534f454653646e6871496977695958566b496a6f695a574a7a6153316a62334a6c4c584e6c636e5a705932567a49697769626d3975593255694f6949314e575935596a566b4d4330795a57457a4c5451334e544d744f474e6c4e5330354e575533597a67784d446c695a4449694c434a7362326470626c396f61573530496a6f695a476c6b58334e70623341694c434a7063334d694f694a6b615751365a574a7a615470365931424f54474a326232705a64476f33556a4e434e6e424b5747464765534a392e633676792d48305839674b4845346c4a7a6174544458526e77447170614f6f4148554e684152335476735a55564c68686a78387a7766465f6172613161355f35654546396d465f5a7536565830413930663939735767222c22646964223a226469643a656273693a7a63504e4c62766f6a59746a3752334236704a58614679222c226e6f6e6365223a2248356c2d646c5858577a6e70587065435655754c375a6d7553493239544a4478753079576f7164553731413d227d"

var testingReceiverPrivkey = []byte{51, 37, 145, 156, 66, 168, 189, 189, 176, 19, 177, 30, 148, 104, 25, 140, 155, 42, 248, 190, 121, 110, 16, 174, 143, 148, 72, 129, 94, 113, 219, 58}

type DidBucketFile struct {
	EncKey json.RawMessage `json:"enc_key,omitempty"`
}

func TestGenerateKey(t *testing.T) {
	_, err := secp256k1.GeneratePrivateKey()
	assert.NoError(t, err)
}

func BenchmarkEncrypt(b *testing.B) {
	privkey, _ := secp256k1.NewPrivateKeyFromBytes(testingReceiverPrivkey)
	EphemPrivateKey, _ := secp256k1.GeneratePrivateKey()

	msg := []byte(testingJsonMessage)
	for i := 0; i < b.N; i++ {
		_, err := EphemPrivateKey.Encrypt(&privkey.PublicKey, msg)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	privkey, _ := secp256k1.NewPrivateKeyFromBytes(testingReceiverPrivkey)
	EphemPrivateKey, _ := secp256k1.GeneratePrivateKey()
	msg := []byte(testingJsonMessage)

	ciphertext, err := EphemPrivateKey.Encrypt(&privkey.PublicKey, msg)
	if err != nil {
		b.Fail()
	}

	for i := 0; i < b.N; i++ {
		_, err := privkey.Decrypt(ciphertext)
		if err != nil {
			b.Fail()
		}
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	privkey, _ := secp256k1.NewPrivateKeyFromBytes(testingReceiverPrivkey)
	EphemPrivateKey, _ := secp256k1.GeneratePrivateKey()
	ciphertext, err := EphemPrivateKey.Encrypt(&privkey.PublicKey, []byte(testingMessage))
	require.Nil(t, err)

	plaintext, err := privkey.Decrypt(ciphertext)
	require.Nil(t, err)

	assert.Equal(t, testingMessage, string(plaintext))
}

func TestEbsiDecrypt(t *testing.T) {
	buf, _ := json.Marshal(testingEncryptionPrivateKey)
	receiverKey, err := jwk.ParseKey(buf)
	require.Nil(t, err)

	privKey, err := secp256k1.NewPrivateKeyFromJwk(receiverKey)
	require.Nil(t, err)

	encryptedPayload := testingAke1Payload["ake1_enc_payload"].(string)
	ciphertext, _ := hex.DecodeString(encryptedPayload)

	plaintext, err := privKey.Decrypt(ciphertext)
	assert.NoError(t, err)
	t.Log(hex.EncodeToString(plaintext))
	assert.Equal(t, expectedDecryptedHex, hex.EncodeToString(plaintext))
}

func TestPublicKeyDecompression(t *testing.T) {
	// Generate public key
	privkey, err := secp256k1.GeneratePrivateKey()
	require.NoError(t, err)

	// Drop Y part and restore it
	kpub := secp256k1.PublicKey{PublicKey: &privkey.PublicKey}
	pubkey, err := secp256k1.NewPublicKeyFromHex(kpub.Hex(true))
	require.NoError(t, err)

	// Check that point is still at curve
	assert.True(t, privkey.IsOnCurve(pubkey.X, pubkey.Y))
}

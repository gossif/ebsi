// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package secp256k1

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

type EciesEncrypted struct {
	Iv             []byte // 16 bits
	EphemPublicKey []byte // 33 bits
	Mac            []byte // 32 bits
	Ciphertext     []byte // variable bits
}

// Encrypt encrypts a passed message with a sender private key and receivers public key,
// returns ecies structure or encryption error
func (k *PrivateKey) Encrypt(pubKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	var (
		eciesBuffer EciesEncrypted
	)
	senderPrivKey := SetPrivateKey(k.PrivateKey)
	EphemPublicKey := senderPrivKey.PublicKey
	// communicate the public key with the receiver
	eciesBuffer.EphemPublicKey = SetPublicKey(&EphemPublicKey).Bytes(true)

	// Derive shared secret
	sharedSecret, err := senderPrivKey.ECDH(pubKey)
	if err != nil {
		return nil, err
	}
	// generate iv
	eciesBuffer.Iv = make([]byte, aes.BlockSize)
	_, err = rand.Read(eciesBuffer.Iv)
	if err != nil {
		return nil, err
	}
	sha512hash := sha512.Sum512(sharedSecret[1:])
	encryptionKey := sha512hash[:32]
	macKey := sha512hash[32:]
	eciesBuffer.Ciphertext, err = aesCBCEnc(encryptionKey, plaintext, eciesBuffer.Iv)
	if err != nil {
		return nil, err
	}
	// Create the bytes to calculate the mac
	eciesBuffer.Mac = generateHMac(eciesBuffer, macKey)

	// Create the ecies bytes
	dataToEcies := make([]byte, 0)
	dataToEcies = append(dataToEcies, eciesBuffer.Iv...)
	dataToEcies = append(dataToEcies, eciesBuffer.EphemPublicKey...)
	dataToEcies = append(dataToEcies, eciesBuffer.Mac...)
	dataToEcies = append(dataToEcies, eciesBuffer.Ciphertext...)

	return dataToEcies, nil
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func (k *PrivateKey) Decrypt(msg []byte) ([]byte, error) {
	//var eciesBuffer EciesEncrypted
	// Message cannot be less than length of public key (33) + nonce (16) + tag (32)
	if len(msg) <= (16 + 33 + 32) {
		return nil, fmt.Errorf("invalid length of message")
	}
	eciesBuffer := EciesEncrypted{
		Iv:             msg[0:16],  // 16 bits
		EphemPublicKey: msg[16:49], // 33 bits
		Mac:            msg[49:81], // 32 bits
		Ciphertext:     msg[81:],   // variable bits
	}
	cipherBytes := make([]byte, len(eciesBuffer.Ciphertext))
	copy(cipherBytes, eciesBuffer.Ciphertext)
	// Ephemeral sender public key
	ethPubkey, err := NewPublicKeyFromBytes(eciesBuffer.EphemPublicKey)
	if err != nil {
		return nil, err
	}
	// Derive shared secret
	sharedSecret, err := ethPubkey.ECDH(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	sha512hash := sha512.Sum512(sharedSecret[1:])
	encryptionKey := sha512hash[:32]
	//macKey := sha512hash[32:]

	plaintext, e := aesCBCDec(encryptionKey, eciesBuffer.Ciphertext, eciesBuffer.Iv)
	if e != nil {
		return nil, err
	}
	// TODO; analyze why value is changed in aesCBCDec
	eciesBuffer.Ciphertext = cipherBytes

	// Create the bytes to calculate the mac
	//checkMac := generateHMac(eciesBuffer, macKey)
	//if !bytes.Equal(checkMac, eciesBuffer.Mac) {
	// do not return an error yet, don't know yet how to calculate the mac properly
	//}

	return plaintext, nil
}

func generateHMac(eciesBuffer EciesEncrypted, macKey []byte) []byte {
	// Create the bytes to calculate the mac
	// Currently, the mac is calculated on the Iv, EphemPublicKey, and Ciphertext
	// Spec on how to calculate the mac is not specified yet for Ebsi, we have to analyse the different possibilities
	dataToMac := make([]byte, 0)
	dataToMac = append(dataToMac, eciesBuffer.Iv...)
	dataToMac = append(dataToMac, eciesBuffer.EphemPublicKey...)
	dataToMac = append(dataToMac, eciesBuffer.Ciphertext...)
	// Calculate the mac
	h := hmac.New(sha256.New, macKey)
	h.Write(dataToMac)
	mac := h.Sum(nil)
	return mac
}

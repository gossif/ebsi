// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package secp256k1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func aesCBCEnc(key []byte, plaintext []byte, iv []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pkcs7Padding(plaintext)

	ciphertext = make([]byte, aes.BlockSize+len(plaintext))

	blockModel := cipher.NewCBCEncrypter(block, iv)

	blockModel.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext[aes.BlockSize:], nil
}

func aesCBCDec(key []byte, ciphertext []byte, iv []byte) (plaintext []byte, err error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	blockModel := cipher.NewCBCDecrypter(block, iv)
	plaintext = ciphertext
	blockModel.CryptBlocks(plaintext, ciphertext)

	plaintext = pkcs7UnPadding(plaintext)
	return plaintext, nil
}

// PKCS7 padding works by appending N bytes with the value of chr(N),
// where N is the number of bytes required to make the final block of data the same size as the block size
// pkcs7Padding uses the AES blocksize for padding
func pkcs7Padding(ciphertext []byte) []byte {
	padding := aes.BlockSize - len(ciphertext)%aes.BlockSize
	if padding < 0 {
		padding = 0
	}
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// Unpad to the original length
func pkcs7UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	if length <= 0 {
		return nil
	}

	unpadding := int(plaintext[length-1])
	if length-unpadding < 0 {
		return nil
	}

	return plaintext[:(length - unpadding)]
}

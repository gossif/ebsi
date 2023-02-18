// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
)

const (
	ebsiMethodName string = "ebsi"
)

type decentralizedIdentifier struct {
	methodName       string
	methodSpecificId string
}

func NewDecentralizedIdentifier() decentralizedIdentifier {
	return decentralizedIdentifier{methodName: ebsiMethodName}
}

func (d *decentralizedIdentifier) ParseIdentifier(did string) error {
	schema := strings.Split(did, ":")
	if len(schema) == 3 {
		switch schema[1] {
		case ebsiMethodName:
			d.methodSpecificId = schema[2]
		default:
			return errors.New("unsupported_method")
		}
		return nil
	}
	return errors.New("invalid_schema")
}

// Generate creates a did schema for the method
func (d *decentralizedIdentifier) GenerateMethodSpecificId() {
	// create a did schema conforming to the method specs for ebsi
	// See the specs at https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+DID+Method
	versionByte := make([]byte, 1)
	copy(versionByte, []byte{0x01})

	subjectIdentifierBytes := make([]byte, 16)
	rand.Read(subjectIdentifierBytes)
	// No error handling, the encoding will only return an error if the selected base is not known
	d.methodSpecificId, _ = multibase.Encode(multibase.Base58BTC, append(versionByte, subjectIdentifierBytes...))
}

func (d *decentralizedIdentifier) String() string {
	return fmt.Sprintf("did:%s:%s", d.methodName, d.methodSpecificId)
}

func (d *decentralizedIdentifier) GetMethodSpecificId() string {
	return d.methodSpecificId
}

// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/gossif/ebsi"
	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
)

func TestGenerateDid(t *testing.T) {
	for scenario, fn := range map[string]func(t *testing.T){
		"conformant with specifications": testGConformantWithSpecifications,
		"conformant with uri syntaxt":    testConformantWithUriSyntaxt,
	} {
		t.Run(scenario, func(t *testing.T) {
			fn(t)
		})
	}
}

func testGConformantWithSpecifications(t *testing.T) {
	did := ebsi.NewDecentralizedIdentifier()
	did.GenerateMethodSpecificId()

	// test that did is multibase encoded base58btc
	actualEncoding, actualBytes, err := multibase.Decode(did.GetMethodSpecificId())
	assert.NoError(t, err)
	assert.EqualValues(t, multibase.Base58BTC, actualEncoding)
	// test that first byte holds version 1
	expectedVersion := []byte{0x01}
	assert.EqualValues(t, expectedVersion[0], actualBytes[0])
	// test that identifier holds random 16 bytes
	actualMethodSpecificId := actualBytes[0:]
	assert.Len(t, actualMethodSpecificId, 17)
}

func testConformantWithUriSyntaxt(t *testing.T) {
	did := ebsi.NewDecentralizedIdentifier()
	did.GenerateMethodSpecificId()

	var validDid = regexp.MustCompile("^did:([a-z]+):(.+)")
	assert.True(t, validDid.MatchString(did.String()))

	actualSyntax := did.String()
	expectedSyntax := fmt.Sprintf("did:ebsi:%s", did.GetMethodSpecificId())
	assert.EqualValues(t, expectedSyntax, actualSyntax)
}

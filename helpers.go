// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
)

func generateRandomBytes(len int) ([]byte, error) {
	randomBytes := make([]byte, len)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func generateNonce() (string, error) {
	nonceBytes, err := generateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(nonceBytes), nil
}

func (e *ebsiTrustList) httpPost(url string, payload string, result interface{}) error {
	req, err := http.NewRequest(http.MethodPost, e.hasBaseUrl+url, strings.NewReader(payload))
	if err != nil {
		return err
	}
	// add authorization header to the req

	if strings.TrimSpace(e.hasAuthToken) != "" {
		req.Header.Add("Authorization", "Bearer "+e.hasAuthToken)
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")
	if strings.TrimSpace(e.hasConformance) != "" {
		req.Header.Add("Conformance", e.hasConformance)
	}
	// Send req using http Client
	if e.hasVerbose {
		body, _ := httputil.DumpRequestOut(req, true)
		fmt.Printf("REQUEST:\n%s\n", string(body))
	}
	resp, err := e.hasHttpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if e.hasVerbose {
		body, _ := httputil.DumpResponse(resp, true)
		fmt.Printf("RESPONSE:\n%s\n", string(body))
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&result)
		if err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("request_failed: %b %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

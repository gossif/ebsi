// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
)

func (e *ebsiTrustList) ResolveDid(did string) (interface{}, error) {
	var diddoc interface{}
	// expect not an error on method allowed
	resp, err := e.hasHttpClient.Get(e.hasBaseUrl + "/did-registry/v3/identifiers/" + did)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if e.hasVerbose {
		body, _ := httputil.DumpResponse(resp, true)
		fmt.Printf("RESPONSE:\n%s\n", string(body))
	}
	switch resp.StatusCode {
	case http.StatusOK:
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&diddoc)
		if err != nil {
			return nil, err
		}
		return diddoc, nil
	default:
		return nil, fmt.Errorf("request_failed: %b %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
}

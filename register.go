// Copyright 2023 The Go SSI Framework Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ebsi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/goccy/go-json"
	"github.com/gossif/ebsi/jcs"
	"github.com/gossif/ebsi/secp256k1"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/ybbus/jsonrpc/v3"
)

type insertDocumentParams struct {
	From               string `json:"from"`
	Identifier         string `json:"identifier"`
	HashAlgorithmId    int    `json:"hashAlgorithmId"`
	HashValue          string `json:"hashValue"`
	DidVersionInfo     string `json:"didVersionInfo"`
	TimestampData      string `json:"timestampData"`
	DidVersionMetadata string `json:"didVersionMetadata"`
}

type unsignedTransaction struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Data     string `json:"data"`
	Value    string `json:"value"`
	Nonce    string `json:"nonce"`
	ChainId  string `json:"chainId"`
	GasLimit string `json:"gasLimit"`
	GasPrice string `json:"gasPrice"`
}

type signedTransactionParams struct {
	Protocol             string              `json:"protocol"`
	UnsignedTransaction  unsignedTransaction `json:"unsignedTransaction"`
	SinatureR            string              `json:"r"`
	SinatureS            string              `json:"s"`
	SinatureV            string              `json:"v"`
	SignedRawTransaction string              `json:"signedRawTransaction"`
}

type registration struct {
	Identifier                                string
	Document                                  map[string]interface{}
	DocumentMetadata                          map[string]interface{}
	Credential                                map[string]interface{}
	SigningKey, EncryptionKey, TransactionKey jwk.Key
}

type registrationOption func(*registration)

func WithController(did string) registrationOption {
	return func(r *registration) {
		r.Identifier = did
	}
}

func WithDocument(doc map[string]interface{}) registrationOption {
	return func(r *registration) {
		r.Document = doc
	}
}

func WithDocumentMetadata(docMetadata map[string]interface{}) registrationOption {
	return func(r *registration) {
		r.DocumentMetadata = docMetadata
	}
}

func WithCredential(credential map[string]interface{}) registrationOption {
	return func(r *registration) {
		r.Credential = credential
	}
}

func WithSigningKey(signingKey jwk.Key) registrationOption {
	return func(r *registration) {
		r.SigningKey = signingKey
	}
}

func WithEncryptionKey(encryptionKey jwk.Key) registrationOption {
	return func(r *registration) {
		r.EncryptionKey = encryptionKey
	}
}

func WithTransactionKey(transactionKey jwk.Key) registrationOption {
	return func(r *registration) {
		r.TransactionKey = transactionKey
	}
}

func (e *ebsiTrustList) RegisterDid(options ...registrationOption) (interface{}, error) {
	var (
		ake1 *ake1Decrypted
		err  error
	)
	ro := registration{}
	for _, opt := range options {
		opt(&ro)
	}
	credential, err := json.Marshal(ro.Credential)
	if err != nil {
		return nil, err
	}
	if ake1, err = e.getAccessToken(ro.Identifier, string(credential), ro.SigningKey, ro.EncryptionKey); err != nil {
		return nil, err
	}
	insertDocumentParams, err := ro.encodeDocumentParams()

	if err != nil {
		return nil, err
	}
	rpcClient := jsonrpc.NewClientWithOpts(e.hasBaseUrl+"/did-registry/v3/jsonrpc", &jsonrpc.RPCClientOpts{
		DefaultRequestID: 1,
		CustomHeaders: map[string]string{
			"Authorization": "Bearer " + ake1.AccessToken,
			"Conformance":   e.hasConformance,
		},
	})
	ctx := context.Background()
	unsignedTxn, err := insertDocumentParams.postUnsignedTxn(ctx, rpcClient)
	if err != nil {
		return nil, err
	}
	return unsignedTxn.postSignedTxn(ctx, rpcClient, ro.TransactionKey)
}

func (b *registration) encodeDocumentParams() (*insertDocumentParams, error) {
	canonicalizedDocument, _ := jcs.Marshal(b.Document)
	hashValueDocument := sha256.Sum256(canonicalizedDocument)

	privKey, err := secp256k1.NewPrivateKeyFromJwk(b.SigningKey)
	if err != nil {
		return nil, err
	}
	pubKey := secp256k1.SetPublicKey(&privKey.PublicKey)
	hexAddress, err := pubKey.GetAdress()
	if err != nil {
		return nil, err
	}
	// Compose the params.
	// The first byte of the hex must be the prefix "0x", the standard hex library doesn't set the prefix
	insertDocumentParams := insertDocumentParams{
		From: hexAddress, // Ethereum address of the signer
		// Beware that in the test environment (https://api.test.intebsi.xyz) you will get an error on the identifier
		// saying that it needs to be a valid did and encoded in hexadecimal.
		// This error is misleading. Preprod doesn't give the error.
		// Might have to do with the conformance identifier, but we didn't analyzed it.
		Identifier:         hexutil.Encode([]byte(b.Identifier)),
		HashAlgorithmId:    0,
		HashValue:          hexutil.Encode(hashValueDocument[:]),
		DidVersionInfo:     jsonStringify2Hex(b.Document),
		TimestampData:      jsonStringify2Hex(map[string]string{"created": time.Now().UTC().Format(time.RFC3339)}),
		DidVersionMetadata: jsonStringify2Hex(b.DocumentMetadata),
	}
	return &insertDocumentParams, nil
}

func (insertDocumentParams *insertDocumentParams) postUnsignedTxn(ctx context.Context, rpcClient jsonrpc.RPCClient) (*unsignedTransaction, error) {
	var (
		unsignedTxn unsignedTransaction
	)
	response, err := rpcClient.Call(ctx, "insertDidDocument", []interface{}{insertDocumentParams})
	if err != nil {
		return nil, err
	}
	result := response.Result.(map[string]interface{})
	unsignedTxn = unsignedTransaction{
		From:     result["from"].(string),
		To:       result["to"].(string),
		Data:     result["data"].(string),
		Value:    result["value"].(string),
		Nonce:    result["nonce"].(string),
		ChainId:  result["chainId"].(string),
		GasLimit: result["gasLimit"].(string),
		GasPrice: result["gasPrice"].(string),
	}

	return &unsignedTxn, nil
}

func (unsignedTxn *unsignedTransaction) postSignedTxn(ctx context.Context, rpcClient jsonrpc.RPCClient, transactionKey jwk.Key) (interface{}, error) {

	data, err := hexutil.Decode(unsignedTxn.Data)
	if err != nil {
		return nil, err
	}
	txn := types.NewTransaction(
		hex2Uint64(unsignedTxn.Nonce),
		common.HexToAddress(unsignedTxn.To),
		hex2BigInt(unsignedTxn.Value),
		hex2Uint64(unsignedTxn.GasLimit),
		hex2BigInt(unsignedTxn.GasPrice),
		data,
	)
	privKey, err := secp256k1.NewPrivateKeyFromJwk(transactionKey)
	if err != nil {
		return nil, err
	}
	signedTxn, err := types.SignTx(txn, types.NewEIP155Signer(hex2BigInt(unsignedTxn.ChainId)), privKey.PrivateKey)
	if err != nil {
		return nil, err
	}
	v, r, s := signedTxn.RawSignatureValues()
	ts := types.Transactions{signedTxn}
	b := new(bytes.Buffer)
	ts.EncodeIndex(0, b)
	rawTxBytes := b.Bytes()

	signedTransactionParams := signedTransactionParams{
		Protocol:             "eth",
		UnsignedTransaction:  *unsignedTxn,
		SinatureR:            hexutil.EncodeBig(r),
		SinatureS:            hexutil.EncodeBig(s),
		SinatureV:            hexutil.EncodeBig(v),
		SignedRawTransaction: hexutil.Encode(rawTxBytes),
	}

	response, err := rpcClient.Call(ctx, "sendSignedTransaction", []interface{}{signedTransactionParams})
	if err != nil {
		return nil, err
	}
	return response, nil
}

func hex2Uint64(hexString string) uint64 {
	// remove 0x suffix if found in the input string
	cleaned := strings.Replace(hexString, "0x", "", -1)

	// base 16 for hexadecimal
	result, _ := strconv.ParseUint(cleaned, 16, 64)
	return uint64(result)
}

func hex2BigInt(hexString string) *big.Int {
	bigInt := new(big.Int)
	// remove 0x suffix if found in the input string
	cleaned := strings.Replace(hexString, "0x", "", -1)
	// base 16 for hexadecimal
	bigInt.SetString(cleaned, 16)
	return bigInt
}

func jsonStringify2Hex(object any) string {
	buf, _ := json.Marshal(object)
	return hexutil.Encode(buf)
}

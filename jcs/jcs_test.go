package jcs_test

import (
	"testing"
	"time"

	"github.com/gossif/ebsi/jcs"
	"github.com/stretchr/testify/assert"
)

func TestCanonicalization(t *testing.T) {
	type testCases struct {
		description    string
		input          any
		expectedOutput string
		expectedError  error
	}

	setBoolValue := func(b bool) *bool { return &b }
	dt, _ := time.Parse(time.RFC3339, "2018-12-17T01:08:19.719Z")

	for _, scenario := range []testCases{
		{description: "strings", input: struct {
			Strings string        `json:"text"`
			Number  float64       `json:"num"`
			Dat     time.Time     `json:"dt"`
			Arr     []interface{} `json:"arr"`
		}{"你好", 47734.12, dt, []interface{}{56, "a", "12", map[string]interface{}{"t": "455A", "a": 123}}}, expectedOutput: `{"arr":[56,"a","12",{"a":123,"t":"455A"}],"dt":"2018-12-17T01:08:19.719Z","num":47734.12,"text":"你好"}`, expectedError: nil},
		{description: "numbers", input: struct {
			Numbers []float64 `json:"numbers"`
		}{[]float64{333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001}}, expectedOutput: `{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}`, expectedError: nil},
		{description: "literals", input: struct {
			Literals []*bool `json:"literals"`
		}{[]*bool{nil, setBoolValue(true), setBoolValue(false)}}, expectedOutput: `{"literals":[null,true,false]}`, expectedError: nil},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			output, actualError := jcs.Marshal(scenario.input)

			assert.ErrorIs(t, actualError, scenario.expectedError)
			assert.EqualValues(t, scenario.expectedOutput, string(output))
		})
	}
}

func TestMUSTOrderTheMembers(t *testing.T) {
	type testCases struct {
		description    string
		input          any
		expectedOutput string
		expectedError  error
	}
	type object struct {
		S string `json:"string"`
		I int    `json:"int"`
		B bool   `json:"bool"`
	}
	type values struct {
		S string  `json:"string"`
		I int     `json:"int"`
		B bool    `json:"bool"`
		N float64 `json:"float"`
		O object  `json:"object"`
	}
	for _, scenario := range []testCases{
		{description: "insignificant space characters elided", input: values{"string of something", 53, true, -1.3344, object{"itsastring", 53, true}}, expectedOutput: `{"bool":true,"float":"-1.3344","int":53,"object":{"bool":true,"int":53,"string":"itsastring"},"string":"string of something"}`, expectedError: nil},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			output, actualError := jcs.Marshal(scenario.input)

			assert.ErrorIs(t, actualError, scenario.expectedError)
			assert.EqualValues(t, scenario.expectedOutput, string(output))
		})
	}
}

func TestMUSTRepresentAllIntegerNumbers(t *testing.T) {
	type testCases struct {
		description    string
		input          any
		expectedOutput string
		expectedError  error
	}
	for _, scenario := range []testCases{
		{description: "must be an integer, otherwise stringify", input: struct {
			F float64 `json:"float"`
			I float64 `json:"int"`
		}{-1.3344, 10}, expectedOutput: `{"float":"-1.3344","int":10}`, expectedError: nil},
		{description: "without a leading minus sign when the value is zero", input: struct {
			N float64 `json:"float"`
		}{-0}, expectedOutput: `{"float":0}`, expectedError: nil},
		{description: "without a decimal point", input: struct {
			N float64 `json:"float"`
		}{5.67}, expectedOutput: `{"float":"5.67"}`, expectedError: nil},
		{description: "without an exponent", input: struct {
			N float64 `json:"float"`
		}{1.01e1}, expectedOutput: `{"float":"10.1"}`, expectedError: nil},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			output, actualError := jcs.Marshal(scenario.input)
			assert.ErrorIs(t, actualError, scenario.expectedError)
			assert.EqualValues(t, scenario.expectedOutput, string(output))
		})
	}
}

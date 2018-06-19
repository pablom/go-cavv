package gocavv

import (
	"encoding/hex"
	"testing"
)

const (
    TEST_PAN_16          string = "4123456789012345"
	TEST_PAN_20          string = "41234567890123451234"
	TEST_S_ATN           string = "7993"
	TEST_I_ATN           uint   = 7993
	TEST_S_AUTH_RC       string = "7"
	TEST_I_AUTH_RC       uint8  = 7
	TEST_S_SECOND_ACODE  string = "00"
	TEST_I_SECOND_ACODE  uint8  = 0
    TEST_KEY_A           string = "0123456789ABCDEF"
	TEST_KEY_B           string = "FEDCBA9876543210"
	TEST_CVV2            int    = 972
)

/* Create test keys */
var keyA, _ = hex.DecodeString(TEST_KEY_A)
var keyB, _ = hex.DecodeString(TEST_KEY_B)

var TEST_S_SERVICE_CODE = TEST_S_AUTH_RC + TEST_S_SECOND_ACODE


func TestVisaCavvOutput(t *testing.T) {
	cvv2, err := generateVisaCavvOutput(TEST_PAN_16, TEST_S_ATN, TEST_S_SERVICE_CODE, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV output: %s\n", err)
	}

	if cvv2 != TEST_CVV2 {
		t.Fatalf("Invalid VISA CAVV output: [%d] expected: [%d]\n", cvv2, TEST_CVV2)
	}
}

func TestVisaCavvOutputInvalidPanLen(t *testing.T) {
	//b := dec2bcd(972)
	//fmt.Printf("==== %s\n", hex.EncodeToString(b))

	_, err := generateVisaCavvOutput(TEST_PAN_20, TEST_S_ATN, TEST_S_SERVICE_CODE, keyA, keyB)
	if err == nil {
		t.Fatalf("Generate VISA CAVV output for PAN 20 digits\n")
	}
}

func TestVisaCavvGenerate(t *testing.T) {
	_, err := GenerateVisaCavv(TEST_PAN_16, TEST_I_ATN, TEST_I_AUTH_RC, TEST_I_SECOND_ACODE, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV: %s\n", err)
	}
}

func TestVisaCavvGenerateAtnRnd(t *testing.T) {
	atn := rangeIn(1000000000000000, 9999999999999999)
	_, err := GenerateVisaCavv(TEST_PAN_16, uint(atn), TEST_I_AUTH_RC, TEST_I_SECOND_ACODE, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV random ATN: %s\n", err)
	}
}
package gocavv

import (
	"encoding/hex"
	"testing"
	"fmt"
)

const (
    TEST_PAN_16       string = "4123456789012345"
	TEST_PAN_20       string = "41234567890123451234"
	TEST_ATN          string = "7993"
	TEST_AUTH_RC      string = "7"
	TEST_SECOND_ACODE string = "00"
    TEST_KEY_A        string = "0123456789ABCDEF"
	TEST_KEY_B        string = "FEDCBA9876543210"
	TEST_CVV2         int = 972
)

/* Create test keys */
var keyA, _ = hex.DecodeString(TEST_KEY_A)
var keyB, _ = hex.DecodeString(TEST_KEY_B)

var TEST_SERVICE_CODE = TEST_AUTH_RC + TEST_SECOND_ACODE


func TestVisaCavv(t *testing.T) {
	cvv2, err := GenerateVisaCavvOutput(TEST_PAN_16, TEST_ATN, TEST_SERVICE_CODE, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV output: %s\n", err)
	}

	if cvv2 != TEST_CVV2 {
		t.Fatalf("Invalid VISA CAVV output: [%d] expected: [%d]\n", cvv2, TEST_CVV2)
	}
}

func TestVisaCavvInvalidPanLen(t *testing.T) {
	b := dec2bcd(972)

	fmt.Printf("==== %s\n", hex.EncodeToString(b))
	_, err := GenerateVisaCavvOutput(TEST_PAN_20, TEST_ATN, TEST_SERVICE_CODE, keyA, keyB)
	if err == nil {
		t.Fatalf("Generate VISA CAVV output for PAN 20 digits\n")
	}
}


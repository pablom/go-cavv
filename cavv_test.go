package gocavv

import (
	"encoding/hex"
	"testing"
)

const (
    TEST_PAN_16          string = "4123456789012345"
	TEST_PAN_20          string = "12344123456789012345"
	TEST_S_ATN           string = "9602231034727993"
	TEST_I_ATN           uint   = 9602231034727993
	TEST_S_AUTH_RC       string = "7"
	TEST_I_AUTH_RC       uint8  = 7
	TEST_S_SECOND_ACODE  string = "00"
	TEST_I_SECOND_ACODE  uint8  = 0
	TEST_I_CAVV_KEY_ID   uint8  = 1
	TEST_I_VER_A_ACTION  uint8  = 0

    TEST_KEY_A           string = "0123456789ABCDEF"
	TEST_KEY_B           string = "FEDCBA9876543210"
	TEST_CVV2            int    = 972
	TEST_RS_CAVV         string = "0700010972799396022310347279930000000000"
)

/* Create test keys */
var keyA, _ = hex.DecodeString(TEST_KEY_A)
var keyB, _ = hex.DecodeString(TEST_KEY_B)

var TEST_S_SERVICE_CODE = TEST_S_AUTH_RC + TEST_S_SECOND_ACODE


func TestVisaCavvOutput(t *testing.T) {
	cvv2, err := generateVisaCavvOutput(TEST_PAN_16, TEST_S_ATN[12:], TEST_S_SERVICE_CODE, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV output for PAN 16 digits: %s\n", err)
	}

	if cvv2 != TEST_CVV2 {
		t.Fatalf("Invalid VISA CAVV output: [%d] expected: [%d]\n", cvv2, TEST_CVV2)
	}
}
/* Test CAVV output generation with 20 digits PAN length */
func TestVisaCavvOutputInvalidPanLen(t *testing.T) {
	cvv2, err := generateVisaCavvOutput(TEST_PAN_20, TEST_S_ATN[12:], TEST_S_SERVICE_CODE, keyA, keyB)
	if err != nil {
		t.Fatalf("Generate VISA CAVV output for PAN 20 digits: %s\n",err)
	}
	if cvv2 != TEST_CVV2 {
		t.Fatalf("Invalid VISA CAVV output: [%d] expected: [%d]\n", cvv2, TEST_CVV2)
	}
}
/* Test CAVV generation with static ATN */
func TestVisaCavvGenerate(t *testing.T) {
	cavv, err := GenerateVisaCavv(TEST_PAN_16, TEST_I_ATN, TEST_I_AUTH_RC, TEST_I_SECOND_ACODE, TEST_I_CAVV_KEY_ID, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV: %s\n", err)
	}
	/* Convert to strring */
	scavv := hex.EncodeToString(cavv)
	if scavv != TEST_RS_CAVV {
		t.Fatalf("Invalid tert VISA CAVV: %s\n\texpected: %s\n", scavv, TEST_RS_CAVV)
	}
}
/* Test CAVV generation with random ATN */
func TestVisaCavvGenerateAtnRnd(t *testing.T) {
	atn := rangeIn(1000000000000000, 9999999999999999)
	_, err := GenerateVisaCavv(TEST_PAN_16, uint(atn), TEST_I_AUTH_RC, TEST_I_SECOND_ACODE, TEST_I_CAVV_KEY_ID, keyA, keyB)
	if err != nil {
		t.Fatalf("Failed to generate VISA CAVV random ATN: %s\n", err)
	}
}

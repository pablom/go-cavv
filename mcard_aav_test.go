package gocavv

import (
	"encoding/hex"
	"testing"
	"strings"
)

const (
	TEST_MC_PAN_1          string = "5432109876543210"
	TEST_MC_PAN_2          string = "50339600000518"
	TEST_MC_PAN_3          string = "530030100000088888"

	TEST_MC_MERCH_NAME     		string = "SPA Merchant, Inc."
	TEST_MC_RS_MNAME_SHA1_HASH 	string = "7CA7FBB6058B5114"

	TEST_MC_ATN                 string = "0047"
	TEST_MC_SERVICE_CODE        string = "140"
	TEST_MC_CVV2                int    = 439

	TEST_MC_CONTOL_BYTE    		uint8  = 0x8C
	TEST_MC_ACS_ID         		uint8  = 0x01
	TEST_MC_ACS_AUTH_METHOD		uint8  = 0x01
	TEST_MC_BIN_KEY_ID		    uint8  = 0x01
	TEST_MC_TSN		            uint32  = 0x0000002F

	TEST_MC_KEY_A  string = "0011223344556677"
	TEST_MC_KEY_B  string = "8899AABBCCDDEEFF"
	TEST_MC_RS_AAV string = "8C7CA7FBB6058B511401110000002F3547BA1EFF"
)

var keyAM, _ = hex.DecodeString(TEST_MC_KEY_A)
var keyBM, _ = hex.DecodeString(TEST_MC_KEY_B)

/* Test Master Card merchant name hash */
func TestMCardMerchantNameAAV(t *testing.T) {
	b := merchantNameHashSPA(TEST_MC_MERCH_NAME)
	if len(b) != 8 {
		t.Fatalf("[MCARD]: Failed to generate merchant name SHA-1 hash\n")
	}

	/* Convert to strring */
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, TEST_MC_RS_MNAME_SHA1_HASH) {
		t.Fatalf("[MCARD]: Invalid hash merchant name VISA CAVV: %s\n\texpected: %s\n", bs, TEST_MC_RS_MNAME_SHA1_HASH)
	}
}
/* Test Master Card AVV CVC2 generation */
/*
func TestMCardGenerationCVC2(t *testing.T) {
	cvc2, err := generateVisaCavvOutput(TEST_MC_PAN_1,TEST_MC_ATN,TEST_MC_SERVICE_CODE, keyAM,keyBM)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate AAV output for PAN 16 digits: %s\n", err)
	}
	if cvc2 != TEST_MC_CVV2 {
		t.Fatalf("[MCARD]: Invalid AAV output (CVC2): [%d] expected: [%d]\n", cvc2, TEST_MC_CVV2)
	}
}
*/
/* Test Master Card AVV */
func TestMCardAvvGenerate(t *testing.T) {
	b, err := GenerateMCardAAV(TEST_MC_PAN_1,TEST_MC_CONTOL_BYTE,TEST_MC_MERCH_NAME,
		TEST_MC_ACS_ID,TEST_MC_ACS_AUTH_METHOD,TEST_MC_BIN_KEY_ID,TEST_MC_TSN,
		keyAM,keyBM)
	if err != nil {
		t.Fatalf("Failed to generate MasterCard AAV: %s\n", err)
	}

	/* Convert to strring */
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, TEST_MC_RS_AAV) {
		t.Fatalf("[MCARD]: Invalid test AAV: %s\n\texpected: %s\n", bs, TEST_MC_RS_AAV)
	}
}

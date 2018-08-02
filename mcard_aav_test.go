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
	TEST_MC_RS_MNAME_SHA1_HASH  string = "7CA7FBB6058B5114"

	TEST_MC_ATN                 string = "0047"
	TEST_MC_SERVICE_CODE        string = "140"
	TEST_MC_CVV2                int    = 439

	TEST_MC_CONTOL_BYTE    		uint8  = 0x8C
	TEST_MC_ACS_ID         		uint8  = 0x01
	TEST_MC_ACS_AUTH_METHOD		uint8  = 0x01
	TEST_MC_BIN_KEY_ID		    uint8  = 0x01
	TEST_MC_TSN		            uint32  = 0x0000002F

	TEST_MC_KEY_A  string = "0011223344556677"
	TEST_MC_KEY_HMAC_20  string = "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"
	TEST_MC_KEY_B  string = "8899AABBCCDDEEFF"
	TEST_MC_RS_AAV string = "8C7CA7FBB6058B511401110000002F3547BA1EFF"
)
/*****************************************************************/
/*     Test Master Card merchant name hash                       */
/*****************************************************************/
func TestMCardMerchantNameHashSPA(t *testing.T) {
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
/*****************************************************************/
/*     Test Master Card AVV hash HMAC-SHA1 generation            */
/*****************************************************************/
func TestMCardHmacSha1(t *testing.T) {
	hash := "3547BA1EFF" /* Expected result hash */
	merchNameHash,_ := hex.DecodeString(TEST_MC_RS_MNAME_SHA1_HASH)
	key, _ := hex.DecodeString(TEST_MC_KEY_HMAC_20) /* Create key from string */
	b, err := generateMCardHmacSha1(TEST_MC_PAN_1,TEST_MC_CONTOL_BYTE,&merchNameHash,
		TEST_MC_ACS_ID,TEST_MC_ACS_AUTH_METHOD,TEST_MC_BIN_KEY_ID,TEST_MC_TSN, key)
	if err != nil {
		t.Fatalf("Failed to generate MasterCard HMAC-SHA1 hash: %s\n", err)
	}
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, hash) {
		t.Fatalf("[MCARD]: Invalid test HMAC-SHA1 hash: %s\n\texpected: %s\n", bs, hash)
	}
}



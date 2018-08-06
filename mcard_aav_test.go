package gocavv

import (
	"encoding/hex"
	"strings"
	"testing"
	"encoding/base64"
)

const (

	TEST_MC_MERCH_NAME         string = "SPA Merchant, Inc."

	TEST_MC_ATN          string = "0047"
	TEST_MC_SERVICE_CODE string = "140"

	TEST_MC_CONTOL_BYTE     uint8  = 0x8C
	TEST_MC_ACS_ID          uint8  = 0x01
	TEST_MC_ACS_AUTH_METHOD uint8  = 0x01
	TEST_MC_BIN_KEY_ID      uint8  = 0x01
	TEST_MC_TSN             uint32 = 0x0000002F
)

/*****************************************************************/
/*     Test Master Card merchant name hash                       */
/*****************************************************************/
func TestMCardMerchantNameHashSPA(t *testing.T) {

	merchNameHash := "7CA7FBB6058B5114"

	b := merchantNameHashSPA(TEST_MC_MERCH_NAME)
	if len(b) != 8 {
		t.Fatalf("[MCARD]: Failed to generate merchant name SHA-1 hash\n")
	}
	/* Convert to strring */
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, merchNameHash) {
		t.Fatalf("[MCARD]: Invalid hash merchant name VISA CAVV: %s\n\texpected: %s\n", bs, merchNameHash)
	}
}
/*****************************************************************/
/*     Test Master Card AVV hash HMAC-SHA1 generation            */
/*****************************************************************/
func TestMCard_AAV_HMAC_SHA1(t *testing.T) {

	pan := "5432109876543210"

	/* Expected result hash for 20 bytes key */
	aav := "8C7CA7FBB6058B511401110000002F3547BA1EFF"
	/* Create key from string */
	key, _ := hex.DecodeString("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
	b, err := GenerateMasterCardAAV( MC_HMAC_SHA1, pan, TEST_MC_CONTOL_BYTE, TEST_MC_MERCH_NAME,
		                             TEST_MC_ACS_ID, TEST_MC_ACS_AUTH_METHOD, TEST_MC_BIN_KEY_ID, TEST_MC_TSN,
		                             nil, nil, key, nil)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard AAV [20 bytes key] with HMAC-SHA1 mac: %s\n", err)
	}
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV [20 bytes key] with HMAC-SHA1 mac: %s\n\texpected: %s\n", bs, aav)
	}

	/* Expected result hash for 16 bytes key */
	aav = "8C7CA7FBB6058B511401110000002FEB27FC7FAB"
	key, _ = hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	b, err = GenerateMasterCardAAV( MC_HMAC_SHA1, pan, TEST_MC_CONTOL_BYTE, TEST_MC_MERCH_NAME,
		                            TEST_MC_ACS_ID, TEST_MC_ACS_AUTH_METHOD, TEST_MC_BIN_KEY_ID, TEST_MC_TSN,
									nil,nil, key, nil)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard AAV [16 bytes key] with HMAC-SHA1 mac: %s\n", err)
	}
	bs = hex.EncodeToString(b)
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV [16 bytes key] with HMAC-SHA1 mac: %s\n\texpected: %s\n", bs, aav)
	}
}
/*****************************************************************/
/*     Test Master Card CVC2 generation                          */
/*****************************************************************/
func TestMCard_CVC2(t *testing.T) {
	atn := "0047"
	scode := "140"
	keyA, _ := hex.DecodeString("0011223344556677")
	keyB, _ := hex.DecodeString("8899AABBCCDDEEFF")

	/* Calculate CVC2 wirh pan length 16 */
	pan := "5432109876543210"
	cvc2 := 439
	c, err := generateCVV2(pan, atn, scode, keyA, keyB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate CVC2: %s\n", err)
	}

	if c != cvc2 {
		t.Fatalf("[MCARD]: Invalid generation CVC2: %d, expected %d\n", c, cvc2)
	}

	/* Calculate CVC2 wirh pan length 18 */
	pan = "530030100000088888"
	cvc2 = 105
	c, err = generateCVV2(pan, atn, scode, keyA, keyB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate CVC2: %s\n", err)
	}

	if c != cvc2 {
		t.Fatalf("[MCARD]: Invalid generation CVC2: %d, expected %d\n", c, cvc2)
	}

	/* Calculate CVC2 wirh pan length 14 */
	pan = "50339600000518"
	cvc2 = 546
	c, err = generateCVV2(pan, atn, scode, keyA, keyB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate CVC2: %s\n", err)
	}

	if c != cvc2 {
		t.Fatalf("[MCARD]: Invalid generation CVC2: %d, expected %d\n", c, cvc2)
	}
}
/*****************************************************************/
/*     Test Master Card AAV generation                           */
/*****************************************************************/
func TestMCard_AAV_CVC2(t *testing.T) {
	keyA, _ := hex.DecodeString("0011223344556677")
	keyB, _ := hex.DecodeString("8899AABBCCDDEEFF")
	acsID := 0x08
	atn := "0047"
	scode := "140"

	/* Calculate AAV with pan length 16 */
	pan := "5432109876543210"
	aav := "8C7CA7FBB6058B511408110000002F0439000000"
	aavb64 := "jHyn+7YFi1EUCBEAAAAvBDkAAAA="
	b, err := GenerateMasterCardAAV( MC_CVC2, pan, TEST_MC_CONTOL_BYTE, TEST_MC_MERCH_NAME,
		uint8(acsID), TEST_MC_ACS_AUTH_METHOD, TEST_MC_BIN_KEY_ID, TEST_MC_TSN,
		&atn,&scode, keyA, keyB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard AAV with CVC2 mac: %s\n", err)
	}
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV with CVC2 mac: %s\n\texpected: %s\n", bs, aav)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(b))
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV [BASE64] with CVC2 mac: %s\n\texpected: %s\n", b64, aavb64)
	}

	/* Calculate AAV with pan length 14 */
	pan = "50339600000518"
	aav = "8C7CA7FBB6058B511408110000002F0546000000"
	aavb64 = "jHyn+7YFi1EUCBEAAAAvBUYAAAA="
	b, err = GenerateMasterCardAAV( MC_CVC2, pan, TEST_MC_CONTOL_BYTE, TEST_MC_MERCH_NAME,
		uint8(acsID), TEST_MC_ACS_AUTH_METHOD, TEST_MC_BIN_KEY_ID, TEST_MC_TSN,
		&atn, &scode, keyA, keyB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard AAV with CVC2 mac: %s\n", err)
	}
	bs = hex.EncodeToString(b)
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV with CVC2 mac: %s\n\texpected: %s\n", bs, aav)
	}
	b64 = base64.StdEncoding.EncodeToString([]byte(b))
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV [BASE64] with CVC2 mac: %s\n\texpected: %s\n", b64, aavb64)
	}

	/* Calculate AAV with pan length 18 */
	pan = "530030100000088888"
	aav = "8C7CA7FBB6058B511408110000002F0105000000"
	aavb64 = "jHyn+7YFi1EUCBEAAAAvAQUAAAA="
	b, err = GenerateMasterCardAAV( MC_CVC2, pan, TEST_MC_CONTOL_BYTE, TEST_MC_MERCH_NAME,
		uint8(acsID), TEST_MC_ACS_AUTH_METHOD, TEST_MC_BIN_KEY_ID, TEST_MC_TSN,
		&atn, &scode, keyA, keyB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard AAV with CVC2 mac: %s\n", err)
	}
	bs = hex.EncodeToString(b)
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV with CVC2 mac: %s\n\texpected: %s\n", bs, aav)
	}
	b64 = base64.StdEncoding.EncodeToString([]byte(b))
	if !strings.EqualFold(bs, aav) {
		t.Fatalf("[MCARD]: Invalid AAV [BASE64] with CVC2 mac: %s\n\texpected: %s\n", b64, aavb64)
	}
}



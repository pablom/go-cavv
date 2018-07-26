package gocavv

import (
	"testing"
	"encoding/hex"
	"strings"
)

const (
	TEST_MC_PAN_1_IAV      string = "5432109876543210"
	TEST_MC_PAN_2_IAV      string = "50339600000518"
	TEST_MC_PAN_3_IAV      string = "530030100000088888"

	TEST_MC_MERCH_NAME_IAV       string = "The Dodgy Dave And Jonty Shop"
	TEST_MC_RS_MNAME_SHA256_HASH string = "943C94EF"
)

/* Test Master Card merchant name hash */
func TestMCardMerchantNameIAV(t *testing.T) {
	b := merchantNameHashSPA2(TEST_MC_MERCH_NAME_IAV)
	if len(b) != 4 {
		t.Fatalf("[MCARD]: Failed to generate merchant name SHA-256 hash\n")
	}

	/* Convert to strring */
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, TEST_MC_RS_MNAME_SHA256_HASH) {
		t.Fatalf("[MCARD]: Invalid hash merchant name VISA IAV: %s\n\texpected: %s\n", bs, TEST_MC_RS_MNAME_SHA256_HASH)
	}
}

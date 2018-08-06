package gocavv

import (
	"testing"
	"encoding/hex"
	"strings"
)

const (
	TEST_MC_MERCH_NAME_IAV       string = "The Dodgy Dave And Jonty Shop"
)
/****************************************************
*  Test Master Card merchant name hash for SPA2
****************************************************/
func TestMCardMerchantNameHashSPA2(t *testing.T) {
	merchNameHash := "943C94EF"
	/* Generate merchant name hash SHA-256*/
	b := merchantNameHashSPA2(TEST_MC_MERCH_NAME_IAV)
	if len(b) != 4 {
		t.Fatalf("[MCARD]: Failed to generate merchant name hash SPA2\n")
	}

	/* Convert to strring */
	bs := hex.EncodeToString(b)
	if !strings.EqualFold(bs, merchNameHash) {
		t.Fatalf("[MCARD]: Invalid hash merchant name SPA2: %s\n\texpected: %s\n", bs, merchNameHash)
	}
}
/****************************************************
*  Test Master Card IAV calculation
****************************************************/
func TestMCard_IAV_CVC2(t *testing.T) {
	/* Create key from string */
	//key, _ := hex.DecodeString("B039878C1F96D212F509B2DC4CC8CD1B")

	/* Calculate IAV with pan length 16 */
	//pan := "2226400099919520"
}


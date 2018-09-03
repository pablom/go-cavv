package gocavv

import (
	"testing"
	"encoding/hex"
	"strings"
	"bytes"
	"encoding/base64"
)

const (
	TEST_MC_MERCH_NAME_IAV  string = "The Dodgy Dave And Jonty Shop"
)
// =============================================================================
// Test Master Card merchant name hash for SPA2
// =============================================================================
func TestMCard_MerchantNameHashSPA2(t *testing.T) {
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
// =============================================================================
// Test amount coding
// =============================================================================
func TestMCard_Amount_Coding(t *testing.T) {
	testAmount := float64(0.0)
	expectedAmount := int64(0x0000)
	amount := codingAmountSPA2(testAmount)
	if amount != expectedAmount {
		t.Fatalf("[MCARD]: Failed to amount coding SPA2: (%X), expected (%X)\n", amount, expectedAmount)
	}

	testAmount = float64(1.0)
	expectedAmount = int64(0x0001)
	amount = codingAmountSPA2(testAmount)
	if amount != expectedAmount {
		t.Fatalf("[MCARD]: Failed to amount coding SPA2: (%X), expected (%X)\n", amount, expectedAmount)
	}

	testAmount = float64(14000.0)
	expectedAmount = int64(0x36B0)
	amount = codingAmountSPA2(testAmount)
	if amount != expectedAmount {
		t.Fatalf("[MCARD]: Failed to amount coding SPA2: (%X), expected (%X)\n", amount, expectedAmount)
	}

	testAmount = float64(14001.0)
	expectedAmount = int64(0x36F1)
	amount = codingAmountSPA2(testAmount)
	if amount != expectedAmount {
		t.Fatalf("[MCARD]: Failed to amount coding SPA2: (%X), expected (%X)\n", amount, expectedAmount)
	}

	testAmount = float64(123456)
	expectedAmount = int64(0x4F24)
	amount = codingAmountSPA2(testAmount)
	if amount != expectedAmount {
		t.Fatalf("[MCARD]: Failed to amount coding SPA2: (%X), expected (%X)\n", amount, expectedAmount)
	}

	testAmount = float64(999999999999)
	expectedAmount = int64(0xFFFF)
	amount = codingAmountSPA2(testAmount)
	if amount != expectedAmount {
		t.Fatalf("[MCARD]: Failed to amount coding SPA2: (%X), expected (%X)\n", amount, expectedAmount)
	}
}
// =============================================================================
// Test Master Card generation MAC for SPA2
// =============================================================================
func TestMCard_Generation_MAC_SPA2(t *testing.T) {
	/* Calculate MAC for SPA2 with pan length 16 */
	pan := "2226400099919520"
	amount := float64(123456)
	currency := uint16(840)
	dsn := uint32(0x2C1C0497)
	mac := "2226400099919520FFFF943C94EF4F2408402C1C0497"

	// Create MAC slice
	b := make([]byte, 22)

	if err := generateMasterCardMACSPA2(&b, pan, TEST_MC_MERCH_NAME_IAV, amount, currency,dsn); err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard mac for SPA2: %s\n", err)
	}
	// Check response IAV buffer
	iavB, _ := hex.DecodeString(mac)
	if !bytes.Equal(iavB, b) {
		t.Fatalf("[MCARD]: Invalid MAC SPA2: %s\n\texpected: %s\n", strings.ToUpper(hex.EncodeToString(b)), mac)
	}
	// Clear slice
	b = nil
}
// =============================================================================
// Test Master Card IAV calculation
// =============================================================================
func TestMCard_Generation_IAV(t *testing.T) {
	pan := "2226400099919520"
	amount := float64(123456)
	currency := uint16(840)
	dsn := uint32(0x2C1C0497)
	secret := "B039878C1F96D212F509B2DC4CC8CD1B"
	secretB,_ := hex.DecodeString(secret)
	iav := "C6041862065500000000000000000000000000000000000000000000"
	iavb64 := "xgQYYgZVAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="  // Expected BAS64 IAV

	b,err := GenerateMasterCardIAV(pan,TEST_MC_MERCH_NAME_IAV,amount,currency,dsn,secretB)
	if err != nil {
		t.Fatalf("[MCARD]: Failed to generate MasterCard IAV: %s\n", err)
	}

	iavB, _ := hex.DecodeString(iav)
	if !bytes.Equal(iavB, b) {
		t.Fatalf("[MCARD]: Invalid IAV: %s\n\texpected: %s\n", strings.ToUpper(hex.EncodeToString(b)), iav)
	}

	b64 := base64.StdEncoding.EncodeToString(b)
	if !strings.EqualFold(b64, iavb64) {
		t.Fatalf("[MCARD]: Invalid IAV [BASE64]: %s\n\texpected: %s\n", b64, iavb64)
	}

	// "18620655A469C3EC4124E19BBD95733BD13A8ABFF63D7FF045E3B166649EC1E6"
}


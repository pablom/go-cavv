package gocavv

import (
	"crypto/sha256"
	"math"
	"fmt"
	"encoding/binary"
	"crypto/hmac"
	"bytes"
)

const (
	MC_IAV_AMOUNT_MAX_EXPLICIT   float64 = 14000
)
// =============================================================================
//  Helper function to create merchant name SHA-1 hash
// =============================================================================
func merchantNameHashSPA2(merchName string)[]byte {
	h := sha256.New()
	h.Write([]byte(merchName))
	bs := h.Sum(nil)
	// Return first 4 bytes, SHA-256 hash of Merchant Name
	return bs[:4]
}
// =============================================================================
// Helper function to coding amount
// =============================================================================
func codingAmountSPA2(amount float64) int64 {
	if amount > MC_IAV_AMOUNT_MAX_EXPLICIT {
		amount = math.Log10(amount/100) * 6553.6
	}
	return int64(amount)
}
// =============================================================================
// Helper function to generate MAC buffer for IAV
// =============================================================================
func generateMasterCardMACSPA2(mac *[]byte, pan string, merchName string,
	                           amount float64, currency uint16, dsn uint32) error {
	// Generate merchant name hash
	h := merchantNameHashSPA2( merchName )
	if len(h) != 4 {
		return fmt.Errorf("Failed to generate merchant name SHA-2 hash length: %d", len(pan))
	}
	// Append PAN to MAC buffer
	if err := appendMasterCardPANtoMacBuffer(mac, pan); err != nil {
		return err
	}
	// Set hash merchant name
	copy((*mac)[10:], h)
	// Set coding amount
	binary.BigEndian.PutUint16((*mac)[14:], uint16(codingAmountSPA2(amount)))
	// Set CAVV output
	copy((*mac)[16:], dec2bcd(uint64(currency))[:2])
	// Set DSN
	binary.BigEndian.PutUint32((*mac)[18:],dsn)
	// Return success response
	return nil
}
// =============================================================================
//  Generate Master Card IAV
// =============================================================================
func GenerateMasterCardIAV(pan string, /* Primary Account Number (PAN) */
	merchName string, /* Merchant name*/
	amount float64, currency uint16, dsn uint32, secret []byte ) ([]byte, error) {

	// Create MAC slice
	mac := make([]byte, 22)
	// Create mac buffer
	if err := generateMasterCardMACSPA2(&mac, pan,merchName,amount,currency,dsn); err != nil {
		return nil, err
	}
	// Calculate HMAC-SHA256
	h := hmac.New(sha256.New, secret)
	h.Write(mac)
	bs := h.Sum(nil)
	// Clear slice
	mac = nil
	// Build output buffer 28 bytes
	iav := bytes.Repeat([]byte{0}, 28)
	iav[0] = 0xC6
	iav[1] = 0x04
	// Copy only first 4 bytes from mac iav
	copy(iav[2:], bs[:4])
	// Return buffer
	return iav, nil
}
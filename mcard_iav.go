package gocavv

import (
	"crypto/sha256"
	"fmt"
)

/********************************************************
  Helper function to create merchant name SHA-1 hash
********************************************************/
func merchantNameHashSPA2( merchName string )[]byte {
	h := sha256.New()
	h.Write([]byte(merchName))
	bs := h.Sum(nil)
	/* Return first 4 bytes, SHA-256 hash of Merchant Name */
	return bs[:4]
}
/********************************************************
  Generate Master Card IAV
********************************************************/
func GenerateMCardIav( pan string, /* Primary Account Number (PAN) */
	merchName string /* Merchant name*/) ([]byte, error) {

	h := merchantNameHashSPA2( merchName )
	if len(h) != 8 {
		return nil, fmt.Errorf("Failed to generate merchant name SHA-1 hash length: %d", len(pan))
	}

	return nil, nil
}
package gocavv

import (
	"testing"
	"encoding/hex"
)

const (
    TEST_PAN  string = "4123456789012345"
)


func TestVisaCavv(t *testing.T) {
	var TEST_ATN = "7993"
	var TEST_AUTH_RC = "7"
	var TEST_SECOND_AUTH_CODE = "00"
	var TEST_KEY_A = "0123456789ABCDEF"

	keyA, _ := hex.DecodeString(TEST_KEY_A)

	generateVisaCavv(TEST_PAN, TEST_ATN, TEST_AUTH_RC, TEST_SECOND_AUTH_CODE, keyA, nil)

	b76a ddce 71cc c6be
	B76A DDCE 71CC C6BE
}
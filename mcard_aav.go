package gocavv

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
)

/*  SPA AAV Format for MasterCard’s Implementation of 3-D Secure:
------------------------------------------------------------------------------------------------------------------------
| Position |  Field Name                       |              Data Source               | Length (bytes) | Byte Number |
------------------------------------------------------------------------------------------------------------------------
|    1     | Control Byte                      | The control byte is used to indicate   |        1       |    Byte 1   |
|          | (Format Version Number)           | the format and content of the          |                |             |
|          |                                   | associated AAV structures. The         |                |             |
|          |                                   | following hexadecimal values have been |                |             |
|          |                                   | defined for MasterCard’s               |                |             |
|          |                                   | implementation of 3-D Secure:          |                |             |
|          |                                   |      • x’8C’ for an AAV created as     |                |             |
|          |                                   |        the result of a successful      |                |             |
|          |                                   |        cardholder authentication.      |                |             |
|          |                                   |      • x’86’ for an AAV created as     |                |             |
|          |                                   |        the result of Attempts          |                |             |
|          |                                   |        processing                      |                |             |
------------------------------------------------------------------------------------------------------------------------
|    2     | Hash of Merchant Name             | The left most 8 bytes of the SHA-1     |        8       |  Bytes 2-9  |
|          |                                   | hash of the Merchant Name field from   |                |             |
|          |                                   | the PAReq.                             |                |             |
------------------------------------------------------------------------------------------------------------------------
|    3     | ACS Identifier                    | Allows an issuer to use up to 256      |        1       |   Byte 10,  |
|          |                                   | different ACS facilities.              |                |             |
|          |                                   |                                        |                |             |
|          |                                   | Values for this field are defined      |                |             |
|          |                                   | based on the algorithm used to create  |                |             |
|          |                                   | the MAC:                               |                |             |
|          |                                   |     0 – 7 Reserved for HMAC            |                |             |
|          |                                   |     8 – 15 Reserved for CVC2           |                |             |
|          |                                   |     16 – 255 – Reserved for future use |                |             |
------------------------------------------------------------------------------------------------------------------------
|    4     | Authentication Method             | Indicates how the cardholder was       |   1⁄2 (4 bits) |   Byte 11,  |
|          |                                   | authenticated to the ACS:              |                | 1 hex digit |
|          |                                   |   0 = No Cardholder Authentication     |                |             |
|          |                                   |       Performed (This is only valid    |                |             |
|          |                                   |       for an AAV created using control |                |             |
|          |                                   |       byte value x’86’ - Attempts      |                |             |
|          |                                   |       processing.)          			|                |             |
|          |                                   |   1 = Password                         |                |             |
|          |                                   |   2 = Secret Key (e.g. Chip Card)      |                |             |
|          |                                   |   3 = PKI (pending further discussions)|                |             |
------------------------------------------------------------------------------------------------------------------------
|    5     | BIN Key Identifier                | Indicates which one of the possible 16 |   1⁄2 (4 bits) |   Byte 11,  |
|          |                                   | issuer-known secret keys for a given   |                |  2 nd hex   |
|          |                                   | BIN range was used by the ACS          |                |   digit     |
|          |                                   | identified by the ACS identifier to    |                |             |
|          |                                   | create the MAC.                        |                |             |
|          |                                   | It is recommended that any given key   |                |             |
|          |                                   | associated with each identifier be     |                |             |
|          |                                   | maintained during the time that a      |                |             |
|          |                                   | chargeback can occur. New keys can     |                |             |
|          |                                   | be rolled into the system by selecting |                |             |
|          |                                   | a new identifier value.                |                |             |
------------------------------------------------------------------------------------------------------------------------
|    6     | Transaction Sequence Number       | Unique number that can be used to      |       4        | Bytes 12-15 |
|          |                                   | identify the transaction within the ACS| (8 hex digits) |             |
|          |                                   | identified by the ACS Identifier field.|                |             |
|          |                                   | Once the maximum value has been        |                |             |
|          |                                   | reached, the number must recycle back  |                |             |
|          |                                   | to 0. Volume permitting, this number   |                |             |
|          |                                   | should be unique for every PARes       |                |             |
|          |                                   | created for a given ACS Identifier     |                |             |
|          |                                   | during the time that a chargeback can  |                |             |
|          |                                   | occur.Use of a random number generator |                |             |
|          |                                   | is permissible as long as the outcome  |                |             |
|          |                                   | is a statistically unique value – the  |                |             |
|          |                                   | last 4 digits of which are likely to be|                |             |
|          |                                   | unique over 10,000 transactions.       |                |             |
------------------------------------------------------------------------------------------------------------------------
|    7     |  MAC                              | Message Authentication Code, created   |       5        | Bytes 16-20 |
|          |                                   | by ACS.                                |                |             |
------------------------------------------------------------------------------------------------------------------------
*/

type MasterCardMacType uint8

const (
	MC_HMAC_SHA1 MasterCardMacType = 0
	MC_CVC2      MasterCardMacType = 1
)

// =============================================================================
//  Helper function to create merchant name SHA-1 hash
// =============================================================================
func merchantNameHashSPA(merchName string) []byte {
	h := sha1.New()
	h.Write([]byte(merchName))
	bs := h.Sum(nil)
	/* Return first 8 bytes, SHA-1 hash of Merchant Name */
	return bs[:8]
}
// =============================================================================
//  Helper function to add 0xFF padding to PAN buffer
//  (20 bytes length)
// =============================================================================
func appendPANpaddingMac(buf *[]byte, i int) {
	n := 10 - i
	for ; n > 0; n-- {
		(*buf)[i] = 0xFF
		i++
	}
}
/********************************************************
*  Helper function to add PAN to mac buffer
********************************************************/
func appendMasterCardPANtoMacBuffer(mac *[]byte, pan string) error {
	// Get PAN length & padding length
	plen := len(pan)
	padlen := plen % 2
	pblen := plen / 2

	if plen < 13 || plen > 19 {
		return fmt.Errorf("Invalid Primary Account Number (PAN) length: %d", len(pan))
	}
	// Convert PAN to int64
	ipan, err := strconv.ParseUint(pan[:(plen-padlen)], 10, 64)
	if err != nil {
		return err
	}
	// Set PAN
	copy(*mac, dec2bcd(ipan))
	// If need haf byte 0x0F padding
	if padlen > 0 {
		v, _ := strconv.ParseUint(pan[(plen-padlen):], 10, 8)
		bm := dec2bcd(v)[0]
		bm = (bm << 4) + 0x0F
		//bm = bm << 4
		//bm |= 0x0F
		(*mac)[pblen] = bm
		pblen++
	}
	// Add additional padding bytes 0xFF
	appendPANpaddingMac(mac, pblen)
	return nil
}
// =============================================================================
//  Helper function to generate MAC for MasterCard AAV
// =============================================================================
func generateMasterCardMACSPA1(
	pan string,        /* Primary Account Number (PAN)         */
	cb uint8,          /* Control Byte (Format Version Number) */
	merchName *[]byte, /* Merchant name hash 8 bytes           */
	acsID uint8,       /* ACS Identifier                       */
	authMethod uint8,  /* ACS Authentication Method            */
	keyID uint8,       /* BIN Key Identifier                   */
	tsn uint32 /* Transaction Sequence Number */) ([]byte, error) {

	// Create MAC slice
	mac := make([]byte, 25)
	// Append PAN to MAC buffer
	if err := appendMasterCardPANtoMacBuffer(&mac, pan); err != nil {
		return nil, err
	}
	// Set control byte
	mac[10] = cb
	// Set hash merchant name
	copy(mac[11:], *merchName)
	// Set ACS Identifier
	mac[19] = acsID
	// Set authentication method & BIN key id
	mac[20] = authMethod<<4 + keyID
	// Set TSN
	binary.BigEndian.PutUint32(mac[21:], tsn)
	return mac, nil
}
// =============================================================================
//  Generate Master Card AAV
// =============================================================================
func GenerateMasterCardAAV(macType MasterCardMacType, /* MAC type */
	pan string,       /* Primary Account Number (PAN) */
	cb uint8,         /* Control Byte (Format Version Number)*/
	merchName string, /* Merchant name*/
	acsID uint8,      /* ACS Identifier */
	authMethod uint8, /* ACS Authentication Method */
	keyID uint8,      /* BIN Key Identifier */
	tsn uint32,       /* Transaction Sequence Number */
	atn *string,
	scode *string,
	keyA, keyB []byte) ([]byte, error) {

	if keyID > 0x0F {
		return nil, fmt.Errorf("Invalid BIN Key Identifier, more than 0x0F: %d", keyID)
	}

	if authMethod > 0x0F {
		return nil, fmt.Errorf("Invalid ACS Authentication Method, more than 0x0F: %d", authMethod)
	}

	// Create merchant name hash
	hmn := merchantNameHashSPA(merchName)
	if len(hmn) != 8 {
		return nil, fmt.Errorf("Failed to generate merchant name hash length: %d", len(hmn))
	}

	// Generate MAC for HMAC-SHA1
	mac, err := generateMasterCardMACSPA1(pan, cb, &hmn, acsID, authMethod, keyID, tsn)
	if err != nil {
		return nil, err
	}

	// create AAV destination buffer (20 bytes)
	aav := make([]byte, 20)
	// Set generated mac to result AAV buffer with 10 bytes skipping
	copy(aav, mac[10:])

	if macType == MC_HMAC_SHA1 {
		// Calculate HMAC-SHA1 hash
		h := hmac.New(sha1.New, keyA)
		h.Write(mac)
		// Set last 5 bytes to result AAV buffer
		copy(aav[15:], h.Sum(nil)[:5])

	} else if macType == MC_CVC2 {
		// Generate CVC2
		cvc2, err := generateCVV2(pan, *atn, *scode, keyA, keyB)
		if err != nil {
			return nil, err
		}
		// Add CVC2
		copy(aav[15:], dec2bcd(uint64(cvc2)))
	}

	return aav, nil
}

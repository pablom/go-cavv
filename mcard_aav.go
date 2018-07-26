package gocavv

import (
	"crypto/sha1"
	"fmt"
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
|    3     | ACS Identifier                    | Allows an issuer to use up to 256      |        1       |   Byte 11,  |
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

/********************************************************
  Helper function to create merchant name SHA-1 hash
********************************************************/
func merchantNameHashSPA( merchName string )[]byte {
	h := sha1.New()
	h.Write([]byte(merchName))
	bs := h.Sum(nil)
	/* Return first 8 bytes, SHA-1 hash of Merchant Name */
	return bs[:8]
}
/********************************************************
  Generate Master Card AAV
********************************************************/
func GenerateMCardAAV( pan string, /* Primary Account Number (PAN) */
	cb uint8,   /* Control Byte (Format Version Number)*/
	merchName string /* Merchant name*/,
	acsId uint8 /* ACS Identifier */,
	keyA, keyB []byte ) ([]byte, error) {

	h := merchantNameHashSPA( merchName )
	if len(h) != 8 {
		return nil, fmt.Errorf("Failed to generate merchant name hash length: %d", len(h))
	}

	/* create AAV destination buffer (20 bytes) */
	aav := make([]byte, 20)

	/* Set control byte */
	aav[0] = 0x8C
	/* Set hash merchant name */
	copy(aav[1:], h)

	/* Set Authentication Results Code */
	//aav[0] = dec2bcd(uint64(arc))[0]

	return nil, nil
}
package gocavv

import (
	"crypto/sha1"
	"fmt"
	"encoding/binary"
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

func generateMCardMAC( pan string,       /* Primary Account Number (PAN) */
                       cb uint8,         /* Control Byte (Format Version Number)*/
	                   merchName string, /* Merchant name*/
	                   acsId uint8,      /* ACS Identifier */
	                   authMethod uint8, /* ACS Authentication Method */
	                   keyId uint8,      /* BIN Key Identifier */
	                   tsn uint32        /* Transaction Sequence Number */) ([]byte, error) {

	/* Get PAN length */
	plen := len(pan)

	if plen < 13 || plen > 19 {
		return nil, fmt.Errorf("Invalid Primary Account Number (PAN) length: %d", len(pan))
	}


	h := merchantNameHashSPA( merchName )
	if len(h) != 8 {
		return nil, fmt.Errorf("Failed to generate merchant name hash length: %d", len(h))
	}

	mac := make([]byte, 25)

	/* Convert PAN to int64 */
	ipan, err := strconv.ParseUint(pan, 10, 64)
	if err != nil {
		return nil, err
	}

	/* Set PAN */
	copy(mac, dec2bcd(ipan))
	mac[8] = 0xFF
	mac[9] = 0xFF
	/* Set control byte */
	mac[10] = cb
	/* Set hash merchant name */
	copy(mac[11:], h)
	/* Set ACS Identifier */
	mac[19] = acsId
	/* Set authentication method & BIN key id */
	mac[20] = authMethod << 4 + keyId
	/* Set TSN */
	binary.BigEndian.PutUint32(mac[21:], tsn)
	return mac,nil
}
/********************************************************
  Generate Master Card AAV
********************************************************/
func GenerateMCardAAV( pan string, /* Primary Account Number (PAN) */
			cb uint8,   		/* Control Byte (Format Version Number)*/
			merchName string    /* Merchant name*/,
			acsId uint8         /* ACS Identifier */,
			authMethod uint8,   /* ACS Authentication Method */
			keyId uint8,        /* BIN Key Identifier */
			tsn uint32,         /* Transaction Sequence Number */
			keyA, keyB []byte ) ([]byte, error) {

	return generateMCardMAC(pan, cb, merchName, acsId,authMethod,keyId,tsn)


	h := merchantNameHashSPA( merchName )
	if len(h) != 8 {
		return nil, fmt.Errorf("Failed to generate merchant name hash length: %d", len(h))
	}

	/* create AAV destination buffer (20 bytes) */
	aav := make([]byte, 20)

	/* Set control byte */
	aav[0] = cb
	/* Set hash merchant name */
	copy(aav[1:], h)
	/* Set ACS Identifier */
	aav[9] = acsId
	/* Set authentication method & BIN key id */
	aav[10] = authMethod << 4 + keyId
	/* Set TSN */
	binary.LittleEndian.PutUint32(aav[11:], tsn)

	return aav, nil
}
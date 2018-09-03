package gocavv

import (
	"fmt"
	"strconv"
)

/*
Table D–2: Converting Transaction Status to Authentication Results Code
---------------------------------------------------------------------------------------------------------------
| Transaction Status |                           Meaning                        | Authentication Results Code |
---------------------------------------------------------------------------------------------------------------
|         Y          |  Authentication Successful                               |              0              |
---------------------------------------------------------------------------------------------------------------
|         U          |  Authentication Could Not Be Performed                   |              5              |
---------------------------------------------------------------------------------------------------------------
|         N          |  Authentication Failed                                   |              9              |
---------------------------------------------------------------------------------------------------------------
|         R          |  Authentication Rejected                                 |              9              |
---------------------------------------------------------------------------------------------------------------
|         A          |  Proof of authentication attempt generated for:          |              7              |
|                    |   • Non-participating issuer, or                         |                             |
|                    |   • Non-participating cardholder of participating issuer |                             |
|                    |----------------------------------------------------------|                             |
|                    |  Proof of authentication attempt generated for           |                             |
|                    |  participating issuer with server not available          |                             |
---------------------------------------------------------------------------------------------------------------

Table D–3: Second Factor Authentication Code Values
----------------------------------------------------------------------------------------------------
| Value |                            Meaning                                 | 3DS 1.0.2 | 3DS 2.0 |
----------------------------------------------------------------------------------------------------
|  00   | 3DS 1.0.2, all authentication methods                              |     •     |         |
----------------------------------------------------------------------------------------------------
|  01   | 3DS 2.0 Challenge flow using Static Passcode                       |           |    •    |
----------------------------------------------------------------------------------------------------
|  02   | 3DS 2.0 Challenge flow using OTP via SMS method                    |           |    •    |
----------------------------------------------------------------------------------------------------
|  03   | 3DS 2.0 Challenge flow using OTP via key fob or card reader method |           |    •    |
----------------------------------------------------------------------------------------------------
|  04   | 3DS 2.0 Challenge flow using OTP via App method                    |           |    •    |
----------------------------------------------------------------------------------------------------
|  05   | 3DS 2.0 Challenge flow using OTP via any other method              |           |    •    |
----------------------------------------------------------------------------------------------------
|  06   | 3DS 2.0 Challenge flow using KBA method                            |           |    •    |
----------------------------------------------------------------------------------------------------
|  07   | 3DS 2.0 Challenge flow using OOB with Biometric method             |           |    •    |
----------------------------------------------------------------------------------------------------
|  08   | 3DS 2.0 Challenge flow using OOB with App login method             |           |    •    |
----------------------------------------------------------------------------------------------------
|  09   | 3DS 2.0 Challenge flow using OOB with any other method             |           |    •    |
----------------------------------------------------------------------------------------------------
|  10   | 3DS 2.0 Challenge flow using any other authentication method       |           |    •    |
----------------------------------------------------------------------------------------------------
|  97   | 3DS 2.0 Frictionless flow, RBA Review 11                           |           |    •    |
----------------------------------------------------------------------------------------------------
|  98   | 3DS 2.0 Attempts Server responding                                 |           |    •    |
----------------------------------------------------------------------------------------------------
|  99   | 3DS 2.0 Frictionless flow, RBA 12                                  |           |    •    |
----------------------------------------------------------------------------------------------------

Table D–7: Assembling CAVV Data Field
------------------------------------------------------------------------------------------------------------------------
| Position |  Field Name                       |              Data Source               | Length (bytes) | Byte Number |
------------------------------------------------------------------------------------------------------------------------
|    1     | Authentication Results Code       | From ACS authentication decision,      |   1 (1 BCD)    |    Byte 1   |
|          |                                   | adapted from authentication            |                |             |
|          |                                   | Transaction Status                     |                |             |
------------------------------------------------------------------------------------------------------------------------
|    2     | Second Factor Authentication Code | From ACS Second Factor Authentication  |   1 (2 BCD)    |    Byte 2   |
------------------------------------------------------------------------------------------------------------------------
|    3     | CAVV Key Indicator                | As determined by keys loaded in VIP    |   1 (1 BCD)    |    Byte 3   |
|          |                                   | and ACS. Permissible values for a      |                |             |
|          |                                   | standard ACS are 01 and 02. An         |                |             |
|          |                                   | Attempts ACS may use values 01 through |                |             |
|          |                                   | 99                                     |                |             |
------------------------------------------------------------------------------------------------------------------------
|    4     | CAVV Output                       | CAVV Output generated by ACS           |   2 (3 BCD)    |  Byte 4-5   |
------------------------------------------------------------------------------------------------------------------------
|    5     | Unpredictable Number              | The four least significant digits of   |   2 (4 BCD)    |  Byte 6-7   |
|          |                                   | the ATN                                |                |             |
------------------------------------------------------------------------------------------------------------------------
|    6     | ATN                               | 16-digit number generated by the ACS   |   8 (16 BCD)   |  Byte 8-15  |
|          |                                   | to identify the transaction            |                |             |
------------------------------------------------------------------------------------------------------------------------
|    7     | Version and Authentication Action | The left nibble identifies the CAVV    |   1 (1 BCD)    |  Byte 16    |
|          |                                   | version. The right nibble identifies   |                |             |
|          |                                   | the authentication action              |                |             |
------------------------------------------------------------------------------------------------------------------------
|    8     | IP Address (in Hex Format)        | CAVV Usage 3, Version 1 (for 3DS1.0.2),|   4 (4 HEX)    | Bytes 17-20 |
|          |                                   | includes the client IP address         |                |             |
|          |                                   | submitted in the authorization message.|                |             |
|          |                                   | CAVV Usage 3, Version 0 (for 3DS 1.0.2 |                |             |
|          |                                   | and 3DS 2.0), IP address is zero       |                |             |
|          |                                   | filled.                                |                |             |
------------------------------------------------------------------------------------------------------------------------
*/

// ===================================================================================================
//  VISA: to calculate CAVV value (using CVV2 with ATN)
//
//  pan - Primary Account Number (PAN) The value that was received in the
//        authentication request message (VEReq, AReq) from the merchant as
//        the Cardholder PAN (16 digits). This same card number will be submitted
//        in the authorization message. Length
//        • If the PAN is Less than 16 digits—The PAN must be right justified and
//          padded on the left with zeros to a total of 16 digits.
//        • If the PAN is Greater than 16 digits—Only the rightmost 16 digits of
//          the PAN must be used.
//          (13-19 digits)
//
//  atn - The four least significant digits of the 4 digits Authentication Tracking Number (ATN).
//        (4 digits)
//
//  scode - Service Code (2 fields) (3 digits)
//          • Authentication Results Code: A value based on the Transaction Status as provided in
//            PARes, ARes,or RReq. Converting Transaction Status to Authentication Results Code
//            for the conversion. (1 digit)
//          • Second Factor: A value based on the result of Authentication Code Second Factor
//            Authentication. (2 digits)
// ==================================================================================================
func GenerateVisaCavv(pan string, /* Primary Account Number (PAN) */
	iatn uint, /* 16-digit number ATN */
	arc uint8, sacode, keyID uint8,
	keyA, keyB []byte) ([]byte, error) {

	// Check Authentication Results Code
	if arc > 9 || arc < 0 {
		return nil, fmt.Errorf("Invalid Authentication Results Code: %d", arc)
	}
	// Convert atn as integer to string
	atn := fmt.Sprintf("%d", iatn)
	// Calculate ATN string length
	alen := len(atn)
	// Check ATN length
	if alen != 16 {
		return nil, fmt.Errorf("Invalid Authentication Tracking Number (ATN) length: %d, expected: 16", alen)
	}
	// Create service code from Authentication Results Code & Second Factor
	scode := fmt.Sprintf("%1d%02d", arc, sacode)
	// Generate CVV2 output
	cvv2, err := generateCVV2(pan, atn[alen-4:], scode, keyA, keyB)
	if err != nil {
		return nil, err
	}

	// create CAVV destination buffer (20 bytes)
	cavv := make([]byte, 20)
	// Set Authentication Results Code
	cavv[0] = dec2bcd(uint64(arc))[0]
	// Set Second Factor Authentication Code
	cavv[1] = dec2bcd(uint64(sacode))[0]
	// Set CAVV Key Indicator
	cavv[2] = dec2bcd(uint64(keyID))[0]
	// Set CAVV output
	copy(cavv[3:], dec2bcd(uint64(cvv2))[:2])
	// Set Unpredictable Number
	atn4digit, _ := strconv.Atoi(atn[alen-4:])
	copy(cavv[5:], dec2bcd(uint64(atn4digit))[:2])
	// Set ATN
	copy(cavv[7:], dec2bcd(uint64(iatn))[:8])
	// Set Version and Authentication Action
	cavv[15] = dec2bcd(uint64(0))[0]

	return cavv, nil
}

package gocavv

import (
    "crypto/cipher"
    "crypto/des"
    "encoding/hex"
    "fmt"
    "strings"
    "regexp"
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

/********************************************************
  Helper function to create cipher from key byte array
********************************************************/
func createKeyCipher(key []byte) (cipher.Block, error) {
    var err error
    var cipher cipher.Block

    /* Create cipher from keyA */
    if len(key) != 24 {
        var tripleDESKey []byte

        if len(key) == 16 {
            tripleDESKey = append(tripleDESKey, key[:16]...)
            tripleDESKey = append(tripleDESKey, key[:8]...)
        } else if len(key) == 8 {
            tripleDESKey = append(tripleDESKey, key[:8]...)
            tripleDESKey = append(tripleDESKey, key[:8]...)
            tripleDESKey = append(tripleDESKey, key[:8]...)
        } else {
            return nil, des.KeySizeError(len(key))
        }

        cipher, err = des.NewTripleDESCipher(tripleDESKey)

    } else {
        cipher, err = des.NewTripleDESCipher(key)
    }
    /* Check return error */
    if err != nil {
        return nil, err
    }

    return cipher, nil
}
/****************************************************************************************
    VISA: to calculate CAVV value (using CVV2 with ATN)

    pan - Primary Account Number (PAN) The value that was received in the
          authentication request message (VEReq, AReq) from the merchant as
          the Cardholder PAN (16 digits). This same card number will be submitted
          in the authorization message. Length
            • If the PAN is Less than 16 digits—The PAN must be right justified and
              padded on the left with zeros to a total of 16 digits.
            • If the PAN is Greater than 16 digits—Only the rightmost 16 digits of
              the PAN must be used.
          (13-19 digits)

    atn - The four least significant digits of the 4 digits Authentication Tracking Number (ATN).
          (4 digits)

    scode - Service Code (2 fields) (3 digits)
            • Authentication Results Code: A value based on the Transaction Status as provided in
                PARes, ARes,or RReq. Converting Transaction Status to Authentication Results Code
                for the conversion. (1 digit)
            • Second Factor: A value based on the result of Authentication Code Second Factor
                Authentication. (2 digits)
******************************************************************************************/
func generateVisaCavvOutput( pan, atn, scode string,  keyA, keyB []byte ) (int, error) {

    var cvv2 string = ""

    /* Get PAN length */
    plen := len(pan)

    if plen < 13 || plen > 19 {
        return 0, fmt.Errorf("Invalid Primary Account Number (PAN) length: %d", len(pan))
    }

    if len(atn) != 4 {
        return 0, fmt.Errorf("Invalid Authentication Tracking Number (ATN) length: %d, expected: 4", len(atn))
    }

    if len(scode) != 3 {
        return 0, fmt.Errorf("Invalid Service Code length: %d, expected: 3", len(scode))
    }

    /* Create cipher from keyA */
    cipherA, err := createKeyCipher(keyA)
    if err != nil {
        return 0, err
    }
    /* Create cipher from keyB */
    cipherB, err := createKeyCipher(keyB)
    if err != nil {
        return 0, err
    }

    if plen > 16 {
        pan = pan[len(pan)-16:]
    } else if plen < 16 {
        pan = pan + strings.Repeat("0", 16 - plen)
    }

    /* Place into 128-bit field padded to the right with binary zeros
       decode PAN, ATN and service code to byte buffer */
    src, err := hex.DecodeString(pan + atn + scode + strings.Repeat("0", 9))
    if err != nil {
        return 0, err
    }

    /* Split field into two 64-bit blocks */
    block1 := src[:8]
    block2 := src[8:]

    /* create temporary destination buffer */
    encBlock1 := make([]byte, 8)
    /* Step 4: Using DES, encrypt Block 1 using Key A */
    cipherA.Encrypt(encBlock1, block1)
    /* Step 5: XOR the result of Step 4 with Block 2, then encrypt the XOR result with Key A */
    for i := 0; i < 8; i++ {
        block1[i] = encBlock1[i] ^ block2[i]
    }
    /* Step 5: using DES, encrypt the XOR result with Key A */
    cipherA.Encrypt(encBlock1, block1)
    /* Step 6: using DES, decrypt the result of step 5 with Key B */
    cipherB.Decrypt(block1,encBlock1)
    /* Step 7: Encrypt the result of Step 6 with Key A */
    cipherA.Encrypt(encBlock1, block1)
    /* Get HEX string from byte buffer */
    hexs := hex.EncodeToString(encBlock1)
    /* Step 8. Extract all digits from 0 through 9 from the result of Step 7 */
    regDigit, err := regexp.Compile("[^0-9]+")
    if err != nil {
        return 0, err
    }
    digitStr := regDigit.ReplaceAllString(hexs, "")
    /* Step 9: Extract the hexadecimal digits from the result of Step 7
       and convert them to numerics by subtracting 10 from each */
    regHex, err := regexp.Compile("[^a-fA-F]+")
    if err != nil {
        return 0, err
    }
    hexStr := regHex.ReplaceAllString(hexs, "")
    for i := range hexStr {
        r0, _ := strconv.ParseUint(string(hexStr[i]), 16, 0)
        cvv2 += strconv.Itoa(int(r0 - 10))
    }
    /* Step 10: Concatenate the result of Step 9 to the result of Step 8 */
    cvv2 = digitStr + cvv2
    /* Step 11: Select the three left-most digits as the CVV2 Output */
    icvv2,_:= strconv.Atoi(cvv2[:3])

    return icvv2, nil
}
/****************************************************************************************

******************************************************************************************/
func GenerateVisaCavv( pan string, /* Primary Account Number (PAN) */
            iatn uint, /* 16-digit number ATN */
            arc uint8, sacode, keyId uint8,
            keyA, keyB []byte ) ([]byte, error) {

    /* Check Authentication Results Code */
    if arc > 9 || arc < 0 {
        return nil, fmt.Errorf("Invalid Authentication Results Code: %d", arc)
    }
    /* Convert atn as integer to string */
    atn := fmt.Sprintf("%d", iatn)
    /* Calculate ATN string length */
    alen := len(atn)
    /* Check ATN length */
    if alen != 16 {
        return nil, fmt.Errorf("Invalid Authentication Tracking Number (ATN) length: %d, expected: 16", alen)
    }
    /* Create service code from Authentication Results Code & Second Factor */
    scode := fmt.Sprintf("%1d%02d", arc, sacode)
    /* Generate CAVV output */
    cvv2,err := generateVisaCavvOutput(pan, atn[alen-4:], scode, keyA, keyB)
    if err != nil {
        return nil, err
    }

    /* create CAVV destination buffer (20 bytes) */
    cavv := make([]byte, 20)
    /* Set Authentication Results Code */
    cavv[0] = dec2bcd(uint64(arc))[0]
    /* Set Second Factor Authentication Code */
    cavv[1] = dec2bcd(uint64(sacode))[0]
    /* Set CAVV Key Indicator */
    cavv[2] = dec2bcd(uint64(keyId))[0]
    /* Set CAVV output */
    copy(cavv[3:], dec2bcd(uint64(cvv2))[:2])
    /* Set Unpredictable Number */
    atn4digit,_ := strconv.Atoi(atn[alen-4:])
    copy(cavv[5:], dec2bcd(uint64(atn4digit))[:2])
    /* Set ATN */
    copy(cavv[7:], dec2bcd(uint64(iatn))[:8])
    /* Set Version and Authentication Action */
    cavv[15] = dec2bcd(uint64(0))[0]

    fmt.Printf("ATN = %s\nATN4 = %s\nCVV2 = %d\n", atn, atn[alen-4:], cvv2)
    return cavv,nil
}
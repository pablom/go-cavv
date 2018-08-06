package gocavv

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)
/**********************************************************
*  Helper function to generate CVC2 for VISA & MasterCard
***********************************************************/
func generateCVV2(pan, atn, scode string, keyA, keyB []byte) (int, error) {

	var cvv2 string

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
		pan = strings.Repeat("0", 16-plen) + pan
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
	cipherB.Decrypt(block1, encBlock1)
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
	icvv2, _ := strconv.Atoi(cvv2[:3])

	return icvv2, nil
}

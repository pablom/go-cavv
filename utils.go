package gocavv

import (
	"math/rand"
	"time"
	"crypto/cipher"
	"crypto/des"
)


func rangeIn(low, hi int) int {
	rand.Seed(time.Now().Unix())
	return low + rand.Intn(hi-low)
}

func dec2bcd(i uint64) []byte {
	var bcd []byte

	if i == 0 {
		bcd = append(bcd,0x0)
		return bcd
	}

	for i > 0 {
		low := i % 10
		i /= 10
		hi := i % 10
		i /= 10
		var x []byte
		x = append(x, byte((hi & 0xf) << 4)|byte(low & 0xf))
		bcd = append(x, bcd[:]...)
	}
	return bcd
}
/*
func decodeBcd(bcd []byte) (x int, err error) {
	for i, b := range bcd {
		hi, lo := int(b>>4), int(b&0x0f)
		if lo == 0x0f && i == len(bcd)-1 {
			x = 10*x + hi
			return
		}
		if hi > 9 || lo > 9 {
			return 0, BadInput
		}
		x = 100*x + 10*hi + lo
	}
	return
}

func decodeBcd2(bcd []byte) (int, error) {
	s := hex.EncodeToString(bcd)
	if s[len(s)-1] == 'f' {
		s = s[:len(s)-1]
	}
	return strconv.Atoi(s)
}
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
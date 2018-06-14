package gocavv

import (
    "crypto/cipher"
    "crypto/des"
    "encoding/hex"
    "fmt"
)

/*
PAN                                4123456789012345
ATN Digits                         7993
Authentication Results Code        7
Second Factor Authentication Code  00
*/
func generateVisaCavv(pan string, atn string, authRc string, secondAuthCode string,  keyA, keyB []byte ) error {
    var err error
    var cipher cipher.Block

    if len(keyA) != 24 {
        var tripleDESKey []byte

        if len(keyA) == 16 {
            tripleDESKey = append(tripleDESKey, keyA[:16]...)
            tripleDESKey = append(tripleDESKey, keyA[:8]...)
        } else if len(keyA) == 8 {
            tripleDESKey = append(tripleDESKey, keyA[:8]...)
            tripleDESKey = append(tripleDESKey, keyA[:8]...)
            tripleDESKey = append(tripleDESKey, keyA[:8]...)
        } else {
            return des.KeySizeError(len(keyA))
        }

        cipher, err = des.NewTripleDESCipher(tripleDESKey)

    } else {
        cipher, err = des.NewTripleDESCipher(keyA)
    }

    if err != nil {
        fmt.Printf("NewTripleDESCipher error\n\n")
        return err
    }

    /* Decode PIN to byte buffer */
    src, err := hex.DecodeString(pan)
    if err != nil {
        fmt.Printf("decode error\n\n")
        return nil
    }

    dst := make([]byte, 8)

    cipher.Encrypt(dst, src)

    fmt.Printf("encrypt Block 1      : %s\n\n", hex.EncodeToString(dst))

    return nil
}
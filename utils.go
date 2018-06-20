package gocavv

import (
	"math/rand"
	"time"
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
		x = append(x, byte((hi & 0xf) << 4)|byte(low&0xf))
		bcd = append(x, bcd[:]...)
	}
	return bcd
}
package server

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash/fnv"
)

// xor XORs key with xorKey byte-by-byte. Callers must guarantee equal lengths;
// mismatched lengths are a programmer error and panic rather than silently corrupt output.
func xor(key []byte, xor []byte) []byte {
	if len(key) != len(xor) {
		panic(fmt.Errorf("xor: key length %d != xor length %d", len(key), len(xor)))
	}
	result := make([]byte, len(xor))
	for i, b := range key {
		result[i] = b ^ xor[i]
	}
	return result
}

func hashSHA256(key []byte) string {
	hasher := sha512.New()
	hasher.Write(key)
	return hex.EncodeToString(hasher.Sum(nil))
}

func hash(s string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return fmt.Sprintf("%v", h.Sum32())
}

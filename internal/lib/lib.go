package lib

import (
	"bytes"
	"hash"
)

func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, paddingText...)
}

func PrfPlus(prf hash.Hash, s []byte, streamLen int) []byte {
	var stream, block []byte
	for i := 1; len(stream) < streamLen; i++ {
		prf.Reset()
		_, _ = prf.Write(append(append(block, s...), byte(i))) // hash.Hash.Write() never return an error
		stream = prf.Sum(stream)
		block = stream[len(stream)-prf.Size():]
	}
	return stream[:streamLen]
}
